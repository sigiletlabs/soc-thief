"""Read-only, bounded collection from the Wazuh indexer.

Records are local collector input, not safe model/report/log output. A caller must
abort its window on CollectorError, roll back progress, and require health review.
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
import ssl
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.client import HTTPException
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from soc_thief.zone import name as report_zone_name

ALLOWED_FIELDS = (
    "@timestamp", "rule.id", "rule.level", "rule.description", "agent.id",
    "agent.name", "decoder.name", "manager.name", "location",
    # Breach signals only. None of these enter a group, so none reach the model, the report
    # or Discord; the runner reads them and keeps only a fixed signal name.
    "rule.groups", "data.srcip", "syscheck.path", "syscheck.event", "syscheck.changed_attributes",
)
# Fields Wazuh stores as a list of short strings.
_LIST_FIELDS = {"rule.groups", "syscheck.changed_attributes"}
_LIST_LIMIT = 64
_REQUIRED_FIELDS = {"@timestamp", "rule.id", "rule.level", "rule.description", "agent.id"}
# Measured: one of 220,154 real events in a day (rule 11) carries no rule.description,
# and failing the whole window on it lost the day. An absent or null description is now this
# fixed placeholder, so the alert is still reported; a wrong type or an empty or oversize value
# is still refused.
MISSING_DESCRIPTION = "[rule description missing]"
_RESPONSE_LIMIT = 8 * 1024 * 1024
# Bounded snapshot lifetime, refreshed by each page request; identifiers grow with shard count.
_PIT_KEEP_ALIVE = "2m"
_PIT_ID_LIMIT = 65536
# Noise profile: aggregation-only reads. 250 groups x ~122 day buckets per page stays well under
# the default search.max_buckets (65,535) and the response cap; 40 pages bound 10,000 groups.
PROFILE_MAX_DAYS = 120
_PROFILE_PAGE_SIZE = 250
_PROFILE_MAX_PAGES = 40
_PROFILE_DAY_BUCKETS = PROFILE_MAX_DAYS + 2
_PROFILE_KEY_LIMIT = 256
_PROFILE_LABEL_LIMIT = 4096
_PROFILE_PATH = ("/wazuh-alerts-*/_search?allow_partial_search_results=false"
                 "&allow_no_indices=false&ignore_unavailable=false")
_PROFILE_BUCKET_KEYS = {"key", "doc_count", "max_level", "days", "description", "agent_name"}
# Agent liveness: one aggregation per fast-path run over at most a week of daily indices.
_LIVENESS_MAX_AGENTS = 500
_LIVENESS_MAX_SPAN = timedelta(days=7)
_AGENT_ID = re.compile(r"[0-9]{3,8}")


class CollectorError(RuntimeError):
    """Collection failed; the window requires review and must not be checkpointed."""


@dataclass(frozen=True)
class CollectorConfig:
    indexer_url: str = field(repr=False)
    username_file: Path = field(repr=False)
    password_file: Path = field(repr=False)
    page_size: int = 500
    max_attempts: int = 3
    ca_file: Path | None = field(default=None, repr=False)
    max_pages: int = 1000

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.indexer_url)
            valid = (
                parsed.scheme == "https" and parsed.hostname and parsed.port != 0
                and parsed.username is None and parsed.password is None
                and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
                and not any(c.isspace() or ord(c) < 32 for c in self.indexer_url)
                and "\\" not in self.indexer_url and "%" not in parsed.netloc
            )
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("indexer endpoint must be a bare HTTPS origin") from None
        for name, upper in (("page_size", 1000), ("max_attempts", 5), ("max_pages", 10000)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= upper:
                raise ValueError(f"{name} is outside its supported bounds")

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> CollectorConfig:
        """Read paths only; there are no inline credential or endpoint fallbacks."""
        env = os.environ if env is None else env
        try:
            endpoint = read_secret(Path(env["WAZUH_INDEXER_URL_FILE"]))
            username = Path(env["WAZUH_INDEXER_USERNAME_FILE"])
            password = Path(env["WAZUH_INDEXER_PASSWORD_FILE"])
            if not all(env[key] for key in (
                "WAZUH_INDEXER_URL_FILE", "WAZUH_INDEXER_USERNAME_FILE", "WAZUH_INDEXER_PASSWORD_FILE"
            )):
                raise ValueError
            ca = Path(env["WAZUH_INDEXER_CA_FILE"]) if env.get("WAZUH_INDEXER_CA_FILE") else None
            return cls(endpoint, username, password, ca_file=ca)
        except (KeyError, TypeError, ValueError):
            raise CollectorError("collector file configuration is invalid or incomplete") from None


# The kernel's overflow uid (/proc/sys/kernel/overflowuid): how host root appears inside the
# rootless container, which cannot map it.
_OVERFLOW_UID = 65534


def owner_controlled(fd: int, info: os.stat_result) -> bool:
    """True for a regular file readable only by its owner, and owned by root or this process.

    One wider case, for systemd credentials handed into the rootless container (measured with
    systemd 255): each arrives as a root-owned 0400 file plus an ACL granting
    the service user read. The ACL mask shows as group read (0440), and host root shows as the
    overflow uid. On a read-only mount only, which the container's credential bind mount always
    is, allow that group read bit and that owner. Group write or execute and any access for other
    stay refused everywhere.
    """
    if not stat.S_ISREG(info.st_mode):
        return False
    if not info.st_mode & 0o077 and info.st_uid in (0, os.geteuid()):
        return True
    return bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY and not info.st_mode & 0o037
                and info.st_uid in (0, os.geteuid(), _OVERFLOW_UID))


def read_secret(path: Path) -> str:
    """Read a bounded private regular file without following a final symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not owner_controlled(stream.fileno(), info):
                raise CollectorError("configuration file must be private and owner-controlled")
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise CollectorError("configuration file exceeds size limit")
        value = raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
        if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise CollectorError("configuration file has invalid content")
        return value
    except (OSError, UnicodeError, ValueError):
        raise CollectorError("configuration file cannot be read safely") from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        fp.close()
        raise CollectorError("indexer redirect refused")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError


# collect() is for daily-scale windows; a window this wide means the caller is misusing it.
_MAX_WINDOW_DATES = 31


def _daily_index_dates(start: datetime, end: datetime) -> list[str]:
    """UTC calendar dates (``YYYY.MM.DD``) touched by the half-open window ``[start, end)``.

    Index membership on the deployed indexer is strictly timestamp-derived: every event's
    ``@timestamp`` falls on its own index's UTC date (measured on a real
    indexer, 109/109 indices, a complete check). This is the boundary between the window and the indices it can touch.
    """
    first = start.astimezone(timezone.utc).date()
    last = (end.astimezone(timezone.utc) - timedelta(microseconds=1)).date()
    count = (last - first).days + 1
    if count < 1 or count > _MAX_WINDOW_DATES:
        raise CollectorError("collection window spans too many daily indices")
    return [(first + timedelta(days=i)).strftime("%Y.%m.%d") for i in range(count)]


def _daily_index_pattern(start: datetime, end: datetime) -> str:
    """Comma-joined per-day wildcards, e.g. ``wazuh-alerts-*-2026.09.21,wazuh-alerts-*-2026.09.22``.

    Never a hardcoded version segment (``wazuh-alerts-4.x-``): that would break collection
    silently on a Wazuh major upgrade. Comma and ``*`` are RFC 3986 path sub-delims, valid
    unescaped in a path segment, and this is how OpenSearch's own multi-index REST syntax
    works, so no percent-encoding is applied.
    """
    return ",".join(f"wazuh-alerts-*-{date}" for date in _daily_index_dates(start, end))


def _index_date(index: str) -> str | None:
    """Return an index name's trailing ``YYYY.MM.DD`` suffix, or None if it has none."""
    if len(index) < 11 or index[-11] != "-":
        return None
    suffix = index[-10:]
    year, month, day = suffix[0:4], suffix[5:7], suffix[8:10]
    if suffix[4] != "." or suffix[7] != "." or not (year.isdigit() and month.isdigit() and day.isdigit()):
        return None
    return suffix


class WazuhIndexerCollector:
    """Fetch filtered source pages. No persistence, inference, or delivery occurs here."""

    def __init__(self, config: CollectorConfig, opener: Callable[..., Any] | None = None,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        self._config = config
        self._sleeper = sleeper
        try:
            context = ssl.create_default_context(cafile=config.ca_file)
        except (OSError, ValueError):
            raise CollectorError("indexer TLS trust configuration failed") from None
        # No ambient proxy credentials or redirects to a different destination.
        self._opener = opener or build_opener(
            ProxyHandler({}), _NoRedirect(), HTTPSHandler(context=context)
        ).open

    def collect(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        """Yield one window from a single point-in-time snapshot, then release it.

        The generator must be exhausted for success: a failed snapshot release after the last
        record is still a CollectorError, so the caller cannot checkpoint that window.
        """
        if start.utcoffset() is None or end.utcoffset() is None or start >= end:
            raise ValueError("start and end must be ordered timezone-aware datetimes")
        pit = self._open_snapshot(start, end)
        completed = False
        try:
            after: list[Any] | None = None
            expected: int | None = None
            received = 0
            for _ in range(self._config.max_pages):
                payload = self._payload(start, end, pit)
                if after is not None:
                    payload["search_after"] = after
                hits, total = self._page(self._search(payload, start, end), pit)
                if expected is not None and expected != total:
                    raise CollectorError("indexer window changed during collection")
                expected = total
                # Validate the entire page before exposing any member of that page.
                records = []
                for hit in hits:
                    record = self._allowlist(hit)
                    timestamp = _timestamp(record["fields"]["@timestamp"])
                    if not start <= timestamp < end:
                        raise CollectorError("indexer returned an event outside the window")
                    cursor = self._cursor(hit, start, end, after)
                    if int(cursor[0]) != _milliseconds(timestamp):
                        raise CollectorError("indexer cursor does not match event timestamp")
                    after = cursor
                    records.append(record)
                received += len(records)
                if received > expected or (len(hits) < self._config.page_size and received != expected):
                    raise CollectorError("indexer result count is inconsistent")
                yield from records
                if received == expected:
                    completed = True
                    return
            raise CollectorError("collection page budget exhausted; split the window")
        finally:
            self._close_snapshot(pit, required=completed)

    def sample_case(self, *, agent_id: str, start: datetime, end: datetime,
                    rule_id: str | None = None, exclude_rule: str | None = None,
                    limit: int = 20) -> tuple[int, tuple[dict[str, Any], ...]]:
        """One bounded, read-only recent-alert query for local investigation.

        The exact hit count and at most ``limit`` allowlisted records are returned.
        This is a point-in-time *view* of one ordinary search, not a durable source
        snapshot or a claim that all matching documents were downloaded.
        """
        def identifier(value: object) -> bool:
            return (type(value) is str and 0 < len(value) <= 64
                    and not any(ord(char) < 32 or ord(char) == 127 for char in value))
        if (not identifier(agent_id) or (rule_id is not None and not identifier(rule_id))
                or (exclude_rule is not None and not identifier(exclude_rule))
                or (rule_id is not None and exclude_rule is not None)
                or type(limit) is not int or not 1 <= limit <= min(50, self._config.page_size)
                or type(start) is not datetime or type(end) is not datetime
                or start.utcoffset() is None or end.utcoffset() is None
                or not timedelta(0) < end - start <= timedelta(days=30)):
            raise CollectorError("investigation query is invalid")
        filters: list[dict[str, Any]] = [
            {"range": {"@timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}},
            {"term": {"agent.id": agent_id}},
        ]
        if rule_id is not None:
            filters.append({"term": {"rule.id": rule_id}})
        query: dict[str, Any] = {"bool": {"filter": filters}}
        if exclude_rule is not None:
            query["bool"]["must_not"] = [{"term": {"rule.id": exclude_rule}}]
        payload = {
            "size": limit, "_source": list(ALLOWED_FIELDS), "track_total_hits": True,
            "timeout": "20s", "sort": [{"@timestamp": {"order": "desc"}},
                                      {"_index": "desc"}, {"_id": "desc"}],
            "query": query,
        }
        response = self._search(payload, start, end)
        hits, total = self._page(response)
        if len(hits) != min(total, limit):
            raise CollectorError("investigation search count is inconsistent")
        results = []
        previous = None
        dates = frozenset(_daily_index_dates(start, end))
        for hit in hits:
            record = self._allowlist(hit)
            fields = record["fields"]
            stamp = _timestamp(fields["@timestamp"])
            if (not start <= stamp < end or _index_date(hit["_index"]) not in dates
                    or fields["agent.id"] != agent_id or (rule_id is not None and fields["rule.id"] != rule_id)
                    or (exclude_rule is not None and fields["rule.id"] == exclude_rule)):
                raise CollectorError("investigation search returned an unexpected event")
            sort = hit.get("sort")
            if (not isinstance(sort, list) or len(sort) != 3
                    or type(sort[0]) not in (str, int) or sort[1:] != [hit["_index"], hit["_id"]]
                    or str(_milliseconds(stamp)) != str(sort[0])):
                raise CollectorError("investigation search sort is invalid")
            cursor = (int(sort[0]), sort[1], sort[2])
            if previous is not None and cursor >= previous:
                raise CollectorError("investigation search order is invalid")
            previous = cursor
            results.append(record)
        return total, tuple(results)

    def agent_last_seen(self, agent_ids: Iterable[str], start: datetime, end: datetime) -> dict[str, datetime]:
        """One aggregation-only read: the latest ``@timestamp`` per listed agent in ``[start, end)``.

        No documents or source fields are requested. An agent with no event in the window is
        absent from the result. Bucket counts must sum to the exact total, so a short read, an
        unlisted agent or a value outside the window fails closed.
        """
        ids = sorted(set(agent_ids))
        if (not 1 <= len(ids) <= _LIVENESS_MAX_AGENTS
                or any(type(agent) is not str or _AGENT_ID.fullmatch(agent) is None for agent in ids)
                or type(start) is not datetime or type(end) is not datetime
                or start.utcoffset() is None or end.utcoffset() is None
                or not timedelta(0) < end - start <= _LIVENESS_MAX_SPAN):
            raise CollectorError("liveness query is invalid")
        payload = {
            "size": 0, "track_total_hits": True, "timeout": "20s",
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": start.astimezone(timezone.utc).isoformat(),
                                          "lt": end.astimezone(timezone.utc).isoformat()}}},
                {"terms": {"agent.id": ids}},
            ]}},
            "aggs": {"agents": {"terms": {"field": "agent.id", "size": len(ids)},
                                "aggs": {"latest": {"max": {"field": "@timestamp"}}}}},
        }
        response = self._search(payload, start, end)
        malformed = CollectorError("indexer liveness aggregation is malformed")
        if not isinstance(response, dict) or response.get("timed_out") is not False or "error" in response:
            raise CollectorError("indexer response is incomplete")
        _require_shards(response)
        if response.get("terminated_early", False) is not False:
            raise CollectorError("indexer shard results are incomplete")
        container = response.get("hits")
        total = container.get("total") if isinstance(container, dict) else None
        if (not isinstance(container, dict) or container.get("hits") != [] or not isinstance(total, dict)
                or total.get("relation") != "eq" or type(total.get("value")) is not int or total["value"] < 0):
            raise CollectorError("indexer result count is invalid")
        aggregations = response.get("aggregations")
        agents = aggregations.get("agents") if isinstance(aggregations, dict) else None
        if (not isinstance(aggregations, dict) or aggregations.keys() != {"agents"} or not isinstance(agents, dict)
                or not agents.keys() <= {"buckets", "sum_other_doc_count", "doc_count_error_upper_bound"}
                or agents.get("sum_other_doc_count", 0) != 0 or agents.get("doc_count_error_upper_bound", 0) != 0
                or not isinstance(agents.get("buckets"), list) or len(agents["buckets"]) > len(ids)):
            raise malformed
        listed, seen, counted = set(ids), {}, 0
        for bucket in agents["buckets"]:
            if not isinstance(bucket, dict) or bucket.keys() != {"key", "doc_count", "latest"}:
                raise malformed
            agent, count, latest = bucket["key"], bucket["doc_count"], bucket["latest"]
            value = latest.get("value") if isinstance(latest, dict) else None
            if (agent not in listed or agent in seen or type(count) is not int or count < 1
                    or not isinstance(latest, dict) or not latest.keys() <= {"value", "value_as_string"}
                    or type(value) not in (int, float) or not math.isfinite(value)):
                raise malformed
            try:
                instant = datetime.fromtimestamp(value / 1000, timezone.utc)
            except (OverflowError, OSError, ValueError):
                raise malformed from None
            if not start <= instant < end:
                raise CollectorError("indexer returned an event outside the window")
            seen[agent] = instant
            counted += count
        if counted != total["value"]:
            raise CollectorError("indexer liveness count is inconsistent")
        return seen

    def verify_metadata(self, start: datetime, end: datetime, *, snapshot: bool = False) -> bool:
        """Verify two source-disabled pages; return False if too few hits to prove advancement.

        Only use with a one-record page and one attempt. No identities or content escape
        this method. Successful verification does not establish least-privilege role scope
        or historical completeness. The CLI adds an external wall-clock deadline. With
        ``snapshot`` both pages use one point in time, which must also be released.
        """
        if (start.utcoffset() is None or end.utcoffset() is None
                or not timedelta(0) < end - start <= timedelta(hours=1)):
            raise ValueError("verification requires an aware window of at most one hour")
        if self._config.page_size != 1 or self._config.max_attempts != 1:
            raise ValueError("verification requires one record and one attempt per page")
        if not snapshot:
            return self._verify_pages(start, end, None)
        pit = self._open_snapshot(start, end)
        completed = False
        try:
            result = self._verify_pages(start, end, pit)
            completed = True
            return result
        finally:
            self._close_snapshot(pit, required=completed)

    def profile(self, start: datetime, end: datetime, *,
                now: datetime | None = None) -> dict[str, Any]:
        """Return exact per-(rule, agent) volume for a closed window using aggregations only.

        No documents or source fields are requested (``size: 0``). Labels are the single most
        frequent keyword value and remain untrusted. Bucket counts must sum to the exact total,
        so a missing group key, a short read, or a changed window fails closed.
        """
        check_profile_window(start, end, now)
        after: dict[str, str] | None = None
        expected: int | None = None
        received = 0
        seen: set[tuple[str, str]] = set()
        groups: list[dict[str, Any]] = []
        for _ in range(_PROFILE_MAX_PAGES):
            payload = self._profile_payload(start, end, after)
            total, rows = self._profile_page(
                self._request("POST", _PROFILE_PATH, payload, self._config.max_attempts))
            if expected is not None and total != expected:
                raise CollectorError("indexer window changed during profiling")
            expected = total
            for row in rows:
                identity = (row["rule_id"], row["agent_id"])
                if identity in seen:
                    raise CollectorError("profile group key repeated")
                seen.add(identity)
                received += row["events"]
                groups.append(row)
            if received > total:
                raise CollectorError("profile bucket count exceeds the exact total")
            if received == total:
                return {"total": total, "groups": groups}
            if not rows:
                raise CollectorError("profile bucket count is short of the exact total")
            after = {"rule_id": rows[-1]["rule_id"], "agent_id": rows[-1]["agent_id"]}
        raise CollectorError("profile page budget exhausted; split the window")

    def _profile_payload(self, start: datetime, end: datetime,
                         after: dict[str, str] | None) -> dict[str, Any]:
        composite: dict[str, Any] = {"size": _PROFILE_PAGE_SIZE, "sources": [
            {"rule_id": {"terms": {"field": "rule.id"}}},
            {"agent_id": {"terms": {"field": "agent.id"}}},
        ]}
        if after is not None:
            composite["after"] = after
        return {
            "size": 0, "track_total_hits": True, "timeout": "25s",
            "query": self._payload(start, end)["query"],
            "aggs": {"groups": {"composite": composite, "aggs": {
                "max_level": {"max": {"field": "rule.level"}},
                "days": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day",
                                            "time_zone": report_zone_name(), "min_doc_count": 1}},
                "description": {"terms": {"field": "rule.description", "size": 1}},
                "agent_name": {"terms": {"field": "agent.name", "size": 1}},
            }}},
        }

    @staticmethod
    def _profile_page(response: Any) -> tuple[int, list[dict[str, Any]]]:
        if not isinstance(response, dict) or response.get("timed_out") is not False or "error" in response:
            raise CollectorError("indexer response is incomplete")
        _require_shards(response)
        if response.get("terminated_early", False) is not False:
            raise CollectorError("indexer shard results are incomplete")
        container = response.get("hits")
        if not isinstance(container, dict) or container.get("hits") != []:
            raise CollectorError("indexer profile response has unexpected hits")
        total = container.get("total")
        if (not isinstance(total, dict) or total.get("relation") != "eq"
                or type(total.get("value")) is not int or total["value"] < 0):
            raise CollectorError("indexer result count is invalid")
        aggregations = response.get("aggregations")
        groups = aggregations.get("groups") if isinstance(aggregations, dict) else None
        if (not isinstance(aggregations, dict) or aggregations.keys() != {"groups"}
                or not isinstance(groups, dict) or not groups.keys() <= {"buckets", "after_key"}
                or not isinstance(groups.get("buckets"), list)
                or len(groups["buckets"]) > _PROFILE_PAGE_SIZE):
            raise CollectorError("indexer profile aggregation is malformed")
        rows = [_profile_row(bucket) for bucket in groups["buckets"]]
        if rows:
            if groups.get("after_key") != {"rule_id": rows[-1]["rule_id"], "agent_id": rows[-1]["agent_id"]}:
                raise CollectorError("indexer profile pagination key is invalid")
        elif "after_key" in groups:
            raise CollectorError("indexer profile pagination key is invalid")
        return total["value"], rows

    def _verify_pages(self, start: datetime, end: datetime, pit: str | None) -> bool:
        payload = self._payload(start, end, pit)
        payload["_source"] = False
        after = None
        expected = None
        for number in range(2):
            if after is not None:
                payload["search_after"] = after
            hits, total = self._page(self._search(payload, start, end), pit)
            if expected is not None and total != expected:
                raise CollectorError("indexer window changed during verification")
            expected = total
            if not hits:
                if total > number:
                    raise CollectorError("indexer verification result count is inconsistent")
                return False
            if total <= number:
                raise CollectorError("indexer verification result count is inconsistent")
            hit = hits[0]
            if not isinstance(hit, dict) or "_source" in hit or "fields" in hit:
                raise CollectorError("indexer verification returned unexpected content")
            after = self._cursor(hit, start, end, after)
        return True

    def _open_snapshot(self, start: datetime, end: datetime) -> str:
        # A retried create whose first attempt reached the server can leak one snapshot;
        # it expires after the bounded keep-alive. Narrowed to the window's own UTC daily
        # indices: wazuh-alerts-* alone opens one shard context per day ever indexed.
        pattern = _daily_index_pattern(start, end)
        response = self._request("POST", f"/{pattern}/_search/point_in_time?keep_alive={_PIT_KEEP_ALIVE}"
                                 "&allow_partial_pit_creation=false&allow_no_indices=false"
                                 "&ignore_unavailable=false", None, self._config.max_attempts)
        if not isinstance(response, dict) or "error" in response or not _valid_pit(response.get("pit_id")):
            raise CollectorError("indexer snapshot creation is invalid")
        _require_shards(response)
        return response["pit_id"]

    def _close_snapshot(self, pit: str, *, required: bool) -> None:
        """Release once without retry; only a successful collection is failed by release errors."""
        try:
            response = self._request("DELETE", "/_search/point_in_time", {"pit_id": [pit]}, 1)
            pits = response.get("pits") if isinstance(response, dict) else None
            if (not isinstance(pits, list) or len(pits) != 1 or not isinstance(pits[0], dict)
                    or pits[0].get("pit_id") != pit or pits[0].get("successful") is not True):
                raise CollectorError("indexer snapshot release failed")
        except Exception:
            if required:
                raise CollectorError("indexer snapshot release failed") from None

    def _payload(self, start: datetime, end: datetime, pit: str | None = None) -> dict[str, Any]:
        return {
            **({"pit": {"id": pit, "keep_alive": _PIT_KEEP_ALIVE}} if pit is not None else {}),
            "size": self._config.page_size, "_source": list(ALLOWED_FIELDS),
            "track_total_hits": True, "timeout": "20s",
            "sort": [{"@timestamp": {"order": "asc"}},
                     {"_index": "asc"}, {"_id": "asc"}],
            "query": {"range": {"@timestamp": {
                "gte": start.astimezone(timezone.utc).isoformat(),
                "lt": end.astimezone(timezone.utc).isoformat(),
            }}},
        }

    @staticmethod
    def _cursor(hit: Any, start: datetime, end: datetime,
                after: list[Any] | None) -> list[Any]:
        if not isinstance(hit, dict):
            raise CollectorError("indexer hit is malformed")
        for key in ("_index", "_id"):
            if not isinstance(hit.get(key), str) or not 1 <= len(hit[key]) <= 1024:
                raise CollectorError("indexer event identity is invalid")
        if not hit["_index"].startswith("wazuh-alerts-"):
            raise CollectorError("indexer event is outside the configured index family")
        # Pin the narrowing's safety argument: index membership is timestamp-derived (measured
        # on a real indexer, 109/109 indices), so an index outside the requested window's own dates is
        # never trusted even if its event's @timestamp happens to fall inside the window.
        if _index_date(hit["_index"]) not in _daily_index_dates(start, end):
            raise CollectorError("indexer event index date is outside the requested window")
        cursor = hit.get("sort")
        if (not isinstance(cursor, list) or len(cursor) != 3
                or not isinstance(cursor[0], (str, int)) or isinstance(cursor[0], bool)
                or cursor[1:] != [hit["_index"], hit["_id"]]):
            raise CollectorError("indexer pagination cursor is invalid")
        try:
            milliseconds = int(cursor[0])
            if str(milliseconds) != str(cursor[0]):
                raise ValueError
        except ValueError:
            raise CollectorError("indexer pagination timestamp is invalid") from None
        # Compare exact timedeltas: float timestamps can round across a millisecond edge.
        instant = timedelta(milliseconds=milliseconds) if abs(milliseconds) < 10**15 else None
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if instant is None or not start - epoch <= instant < end - epoch:
            raise CollectorError("indexer cursor is outside the window")
        if after is not None and (milliseconds, *cursor[1:]) <= (int(after[0]), *after[1:]):
            raise CollectorError("indexer pagination did not advance")
        return cursor

    def _page(self, response: Any, pit: str | None = None) -> tuple[list[Any], int]:
        if not isinstance(response, dict) or response.get("timed_out") is not False or "error" in response:
            raise CollectorError("indexer response is incomplete")
        _require_shards(response)
        if response.get("terminated_early", False) is not False:
            raise CollectorError("indexer shard results are incomplete")
        # A changed or unexpected snapshot identity cannot prove one consistent window.
        if "pit_id" in response and (pit is None or response["pit_id"] != pit):
            raise CollectorError("indexer snapshot identity changed")
        container = response.get("hits")
        if not isinstance(container, dict) or not isinstance(container.get("hits"), list):
            raise CollectorError("indexer response has invalid hits")
        total = container.get("total")
        if (not isinstance(total, dict) or total.get("relation") != "eq"
                or type(total.get("value")) is not int or total["value"] < 0
                or len(container["hits"]) > self._config.page_size):
            raise CollectorError("indexer result count is invalid")
        return container["hits"], total["value"]

    def _search(self, payload: dict[str, Any], start: datetime, end: datetime) -> dict[str, Any]:
        # A point-in-time search names no index; its indices were fixed at snapshot creation.
        # The non-PIT branch (verify_metadata without --snapshot) is narrowed the same way.
        path = ("/_search?allow_partial_search_results=false" if "pit" in payload else
                f"/{_daily_index_pattern(start, end)}/_search?allow_partial_search_results=false"
                "&allow_no_indices=false&ignore_unavailable=false")
        return self._request("POST", path, payload, self._config.max_attempts)

    def _request(self, method: str, path: str, payload: dict[str, Any] | None, attempts: int) -> Any:
        username = read_secret(self._config.username_file)
        password = read_secret(self._config.password_file)
        if ":" in username:
            raise CollectorError("indexer username has invalid content")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(
            self._config.indexer_url.rstrip("/") + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers=headers, method=method,
        )
        for attempt in range(attempts):
            try:
                with self._opener(request, timeout=30) as response:
                    if response.status != 200:
                        raise CollectorError("indexer returned an unexpected response status")
                    raw = response.read(_RESPONSE_LIMIT + 1)
                if len(raw) > _RESPONSE_LIMIT:
                    raise CollectorError("indexer response exceeds size limit")
                return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except HTTPError as exc:
                retry = exc.code in (429, 502, 503, 504)
                exc.close()
                if not retry:
                    raise CollectorError("indexer request rejected") from None
            except ssl.SSLError:
                raise CollectorError("indexer TLS verification failed") from None
            except (OSError, HTTPException):
                pass
            except (ValueError, UnicodeError, RecursionError):
                raise CollectorError("indexer response is malformed") from None
            if attempt + 1 == attempts:
                raise CollectorError("indexer search failed") from None
            self._sleeper(2**attempt)
        raise AssertionError("unreachable")

    @staticmethod
    def _allowlist(hit: Any) -> dict[str, Any]:
        if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
            raise CollectorError("indexer hit is malformed")
        for key in ("_index", "_id"):
            if not isinstance(hit.get(key), str) or not 1 <= len(hit[key]) <= 1024:
                raise CollectorError("indexer event identity is invalid")
        if not hit["_index"].startswith("wazuh-alerts-"):
            raise CollectorError("indexer event is outside the configured index family")
        fields = {name: _nested(hit["_source"], name) for name in ALLOWED_FIELDS}
        if fields["rule.description"] is None:
            fields["rule.description"] = MISSING_DESCRIPTION
        for name, value in fields.items():
            if value is None and name not in _REQUIRED_FIELDS:
                continue
            if name == "rule.level":
                if type(value) is int and 0 <= value <= 16:
                    continue
            elif name in _LIST_FIELDS:
                if (type(value) is list and len(value) <= _LIST_LIMIT
                        and all(type(item) is str and 0 < len(item) <= 256 for item in value)):
                    continue
            elif isinstance(value, str) and 0 < len(value) <= (4096 if name == "rule.description" else 1024):
                continue
            raise CollectorError("indexer event field is invalid or missing")
        return {"source_key": {"index": hit["_index"], "id": hit["_id"]}, "fields": fields}


def check_profile_window(start: datetime, end: datetime, now: datetime | None = None) -> None:
    """Require an aware, ordered, closed window of at most ``PROFILE_MAX_DAYS``."""
    if start.utcoffset() is None or end.utcoffset() is None:
        raise ValueError("profile window must be timezone-aware")
    now = datetime.now(timezone.utc) if now is None else now
    if not timedelta(0) < end - start <= timedelta(days=PROFILE_MAX_DAYS) or end > now:
        raise ValueError("profile window must be ordered, closed, and within the day limit")


def _profile_text(value: Any, limit: int) -> bool:
    return type(value) is str and 1 <= len(value) <= limit


def _profile_row(bucket: Any) -> dict[str, Any]:
    malformed = CollectorError("indexer profile bucket is malformed")
    if not isinstance(bucket, dict) or bucket.keys() != _PROFILE_BUCKET_KEYS:
        raise malformed
    key, count, level, days = bucket["key"], bucket["doc_count"], bucket["max_level"], bucket["days"]
    if (not isinstance(key, dict) or key.keys() != {"rule_id", "agent_id"}
            or not all(_profile_text(key[name], _PROFILE_KEY_LIMIT) for name in key)):
        raise malformed
    if type(count) is not int or count < 1:
        raise malformed
    value = level.get("value") if isinstance(level, dict) else None
    if (not isinstance(level, dict) or not level.keys() <= {"value", "value_as_string"}
            or type(value) not in (int, float) or not math.isfinite(value)
            or value != int(value) or not 0 <= value <= 16):
        raise malformed
    histogram = days.get("buckets") if isinstance(days, dict) else None
    if (not isinstance(days, dict) or days.keys() != {"buckets"} or not isinstance(histogram, list)
            or not 1 <= len(histogram) <= _PROFILE_DAY_BUCKETS):
        raise malformed
    day_keys: set[int] = set()
    day_total = 0
    for item in histogram:
        if (not isinstance(item, dict) or not item.keys() <= {"key", "key_as_string", "doc_count"}
                or type(item.get("key")) is not int or type(item.get("doc_count")) is not int
                or item["doc_count"] < 1 or item["key"] in day_keys):
            raise malformed
        day_keys.add(item["key"])
        day_total += item["doc_count"]
    if day_total != count:
        raise malformed
    description, description_complete = _profile_label(bucket["description"], count)
    agent_name, agent_name_complete = _profile_label(bucket["agent_name"], count)
    return {
        "rule_id": key["rule_id"], "agent_id": key["agent_id"], "events": count,
        "max_level": int(value), "days_active": len(histogram),
        "rule_description": description, "description_complete": description_complete,
        "agent_name": agent_name, "agent_name_complete": agent_name_complete,
    }


def _profile_label(aggregation: Any, count: int) -> tuple[str | None, bool]:
    """Return the top keyword and whether that one value covers every event in the group."""
    malformed = CollectorError("indexer profile bucket is malformed")
    if (not isinstance(aggregation, dict)
            or not aggregation.keys() <= {"buckets", "sum_other_doc_count", "doc_count_error_upper_bound"}):
        raise malformed
    buckets, other = aggregation.get("buckets"), aggregation.get("sum_other_doc_count")
    error = aggregation.get("doc_count_error_upper_bound", 0)
    if (not isinstance(buckets, list) or len(buckets) > 1 or type(other) is not int or other < 0
            or type(error) is not int or error < 0):
        raise malformed
    if not buckets:
        if other:
            raise malformed
        return None, False
    item = buckets[0]
    if (not isinstance(item, dict) or item.keys() != {"key", "doc_count"}
            or not _profile_text(item["key"], _PROFILE_LABEL_LIMIT)
            or type(item["doc_count"]) is not int or not 1 <= item["doc_count"] <= count - other):
        raise malformed
    return item["key"], item["doc_count"] == count


def _valid_pit(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= _PIT_ID_LIMIT and all(33 <= ord(c) <= 126 for c in value)


def _require_shards(response: dict[str, Any]) -> None:
    shards = response.get("_shards")
    if (not isinstance(shards, dict)
            or any(type(shards.get(k)) is not int or shards[k] < 0 for k in ("total", "successful", "failed"))
            or shards["total"] == 0 or shards["failed"] != 0
            or shards["successful"] != shards["total"] or shards.get("failures")):
        raise CollectorError("indexer shard results are incomplete")


def _timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError
        return result
    except ValueError:
        raise CollectorError("indexer event timestamp is invalid") from None


def _nested(source: dict[str, Any], path: str) -> Any:
    value: Any = source
    for part in path.split("."):
        if not isinstance(value, dict):
            raise CollectorError("indexer event field structure is invalid")
        if part not in value:
            return None
        value = value[part]
    return value


def _milliseconds(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
