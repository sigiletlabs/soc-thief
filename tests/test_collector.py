"""Synthetic collector contract and transport safety tests; no live services."""

import io
import json
import ssl
import tempfile
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler
from zoneinfo import ZoneInfo

from soc_thief.collector import (
    ALLOWED_FIELDS, MISSING_DESCRIPTION, CollectorConfig, CollectorError, WazuhIndexerCollector,
    _NoRedirect, _RESPONSE_LIMIT, owner_controlled, read_secret,
)

# Reserved synthetic origin only; never use deployment configuration in tests.
ORIGIN = "https://example.invalid"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = datetime(2026, 1, 2, tzinfo=timezone.utc)


# Real daily indices are named wazuh-alerts-4.x-YYYY.MM.DD; the trailing date must fall on
# START's UTC date (2026-01-01) so fixtures pass the timestamp-derived index-date check by
# default. Individual tests that need a different date pass their own `index`.
def hit(identifier="synthetic-1", index="wazuh-alerts-synthetic-a-2026.01.01"):
    return {
        "_index": index, "_id": identifier,
        "sort": [str(int(START.timestamp() * 1000)), index, identifier],
        "_source": {
            "@timestamp": START.isoformat(),
            "rule": {"id": "synthetic-rule", "level": 3, "description": "Synthetic event"},
            "agent": {"id": "synthetic-agent"},
            "command": "synthetic-denied-field",
        },
    }


def page(hits, total=None):
    return {
        "timed_out": False, "_shards": {"total": 2, "successful": 2, "failed": 0},
        "hits": {"hits": hits, "total": {"value": len(hits) if total is None else total, "relation": "eq"}},
    }


PIT = "synthetic-pit-id-marker=="


def created(identifier=PIT):
    return {"pit_id": identifier, "_shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
            "creation_time": 1767225600000}


def deleted(identifier=PIT, successful=True):
    return {"pits": [{"pit_id": identifier, "successful": successful}]}


class Response(io.BytesIO):
    status = 200


def responses(*items):
    return [item if isinstance(item, BaseException) else Response(json.dumps(item).encode()) for item in items]


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.user = self.secret("username", "synthetic-user")
        self.password = self.secret("password", "synthetic-password")
        self.config = CollectorConfig(ORIGIN, self.user, self.password, page_size=1)
        self.sleeper = Mock()
        self.opener = Mock()

    def secret(self, name, value):
        path = self.root / name
        path.write_text(value)
        path.chmod(0o600)
        return path

    def collector(self, *pages, config=None):
        self.opener.side_effect = responses(created(), *pages, deleted())
        return WazuhIndexerCollector(config or self.config, self.opener, self.sleeper)

    def collect(self, *pages, config=None):
        return list(self.collector(*pages, config=config).collect(START, END))

    def test_pagination_preserves_same_id_across_indices(self):
        first = hit()
        second = hit(index="wazuh-alerts-synthetic-b-2026.01.01")
        records = self.collect(page([first], 2), page([second], 2))
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["source_key"], records[1]["source_key"])
        self.assertEqual(set(records[0]["fields"]), set(ALLOWED_FIELDS))
        self.assertNotIn("command", records[0]["fields"])
        request = self.opener.call_args_list[2].args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload["search_after"], first["sort"])
        self.assertEqual(payload["query"]["range"]["@timestamp"], {"gte": START.isoformat(), "lt": END.isoformat()})
        self.assertEqual(payload["_source"], list(ALLOWED_FIELDS))
        self.assertIn("allow_partial_search_results=false", request.full_url)
        self.assertEqual(request.method, "POST")

    def test_verified_empty_window(self):
        self.assertEqual(self.collect(page([])), [])

    def test_rejects_incomplete_pages(self):
        cases = [None, [], {}, {"hits": {}}, page([])]
        cases[-1]["timed_out"] = True
        for field, value in [("failed", 1), ("successful", 1), ("total", 0), ("total", True)]:
            bad = page([]); bad["_shards"][field] = value; cases.append(bad)
        for key, value in [("terminated_early", True), ("error", "synthetic-error"), ("hits", None)]:
            bad = page([]); bad[key] = value; cases.append(bad)
        bad = page([]); del bad["timed_out"]; cases.append(bad)
        bad = page([]); bad["hits"]["total"]["relation"] = "gte"; cases.append(bad)
        cases.extend([page([], 1), page([hit()], 0), page([hit(), hit()], 2)])
        for bad in cases:
            with self.subTest(case=cases.index(bad)), self.assertRaises(CollectorError):
                self.collect(bad)

    def test_changed_count_and_premature_end_fail(self):
        for second in [page([], 2), page([], 1)]:
            with self.assertRaises(CollectorError):
                self.collect(page([hit()], 2), second)

    def test_replayed_or_backwards_cursor_fails(self):
        for second in [hit(), hit("synthetic-0")]:
            with self.assertRaises(CollectorError):
                self.collect(page([hit()], 2), page([second], 2))

    def test_invalid_later_member_prevents_entire_page_emission(self):
        bad = hit("synthetic-2"); bad["_source"]["rule"]["level"] = True
        config = CollectorConfig(ORIGIN, self.user, self.password, page_size=2)
        iterator = self.collector(page([hit(), bad]), config=config).collect(START, END)
        with self.assertRaises(CollectorError):
            next(iterator)

    def test_breach_fields_are_collected_and_lists_are_validated(self):
        # The only list-valued fields; anything else in them refuses the hit.
        good = hit()
        good["_source"]["rule"]["groups"] = ["ossec", "syscheck"]
        good["_source"]["data"] = {"srcip": "198.51.100.7", "win": {"eventdata": {"commandLine": "denied"}}}
        good["_source"]["syscheck"] = {"path": "/etc/shadow", "event": "modified",
                                       "changed_attributes": ["size", "sha256"], "diff": "denied"}
        (record,) = self.collect(page([good]))
        fields = record["fields"]
        self.assertEqual((fields["rule.groups"], fields["data.srcip"], fields["syscheck.path"],
                          fields["syscheck.event"], fields["syscheck.changed_attributes"]),
                         (["ossec", "syscheck"], "198.51.100.7", "/etc/shadow", "modified", ["size", "sha256"]))
        self.assertNotIn("denied", repr(record))
        self.assertIsNone(self.collect(page([hit()]))[0]["fields"]["rule.groups"])
        for value in ("syscheck", [1], [""], ["x" * 257], ["x"] * 65, {"a": 1}):
            bad = hit(); bad["_source"]["rule"]["groups"] = value
            with self.subTest(value=value), self.assertRaises(CollectorError):
                self.collect(page([bad]))

    def test_invalid_hit_shapes_fields_and_cursors_fail(self):
        cases = [None, {}, hit()]
        cases[-1]["_source"] = []
        for key, value in [("_id", None), ("_index", "synthetic-other"), ("sort", None),
                           ("sort", ["0", "synthetic", "synthetic"]),
                           ("sort", ["bad", "wazuh-alerts-synthetic-a", "synthetic-1"])]:
            bad = hit(); bad[key] = value; cases.append(bad)
        for key, value in [("rule", []), ("agent", "synthetic"), ("@timestamp", END.isoformat()),
                           ("@timestamp", "invalid"), ("@timestamp", "2026-01-01")]:
            bad = hit(); bad["_source"][key] = value; cases.append(bad)
        for key, value in [("level", True), ("level", 17), ("description", {}),
                           ("description", "x" * 4097), ("id", "")]:
            bad = hit(); bad["_source"]["rule"][key] = value; cases.append(bad)
        for key in ("id", "level", "description"):
            bad = hit(); bad["_source"]["rule"][key] = ""; cases.append(bad)
        for key in ("id", "level"):
            bad = hit(); del bad["_source"]["rule"][key]; cases.append(bad)
        for i, bad in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(CollectorError):
                self.collect(page([bad]))

    def test_missing_rule_description_is_reported_with_a_placeholder(self):
        # Measured: one real event in 220,154 (rule 11) has no description. It must be
        # reported, not fail the window. An explicit null is treated the same way.
        absent = hit("synthetic-1"); del absent["_source"]["rule"]["description"]
        null = hit("synthetic-2"); null["_source"]["rule"]["description"] = None
        config = CollectorConfig(ORIGIN, self.user, self.password, page_size=2)
        records = list(self.collector(page([absent, null]), config=config).collect(START, END))
        self.assertEqual([r["fields"]["rule.description"] for r in records], [MISSING_DESCRIPTION] * 2)

    def test_page_budget_exhaustion_fails(self):
        config = CollectorConfig(ORIGIN, self.user, self.password, page_size=1, max_pages=1)
        with self.assertRaises(CollectorError):
            self.collect(page([hit()], 2), config=config)

    def test_window_validation(self):
        collector = self.collector()
        for start, end in [(START, START), (END, START), (START.replace(tzinfo=None), END)]:
            with self.assertRaises(ValueError):
                list(collector.collect(start, end))
        self.opener.assert_not_called()

    def test_case_sample_is_scoped_bounded_and_allowlisted(self):
        response = page([hit()], 3)
        self.opener.side_effect = responses(response)
        total, records = WazuhIndexerCollector(self.config, self.opener).sample_case(
            agent_id="synthetic-agent", rule_id="synthetic-rule", start=START, end=END, limit=1)
        self.assertEqual(total, 3)
        self.assertEqual(len(records), 1)
        self.assertNotIn("command", records[0]["fields"])
        request = self.opener.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload["size"], 1)
        self.assertEqual(payload["_source"], list(ALLOWED_FIELDS))
        self.assertEqual(payload["query"]["bool"]["filter"][1], {"term": {"agent.id": "synthetic-agent"}})
        self.assertEqual(payload["query"]["bool"]["filter"][2], {"term": {"rule.id": "synthetic-rule"}})

    def test_case_sample_rejects_wrong_identity_or_partial_response(self):
        for response in (page([hit()], 0), page([], 1), page([hit("synthetic-2")]),
                         {**page([hit()]), "timed_out": True}):
            self.opener.side_effect = responses(response)
            with self.assertRaises(CollectorError):
                WazuhIndexerCollector(self.config, self.opener).sample_case(
                    agent_id="different-agent", start=START, end=END, limit=1)
        self.opener.reset_mock()
        with self.assertRaises(CollectorError):
            WazuhIndexerCollector(self.config, self.opener).sample_case(
                agent_id="synthetic-agent", start=START, end=END + timedelta(days=31), limit=1)
        self.opener.assert_not_called()

    def test_response_size_is_bounded(self):
        response = Response(b" " * (_RESPONSE_LIMIT + 1))
        self.opener.side_effect = [response]
        with self.assertRaisesRegex(CollectorError, "size limit"):
            list(WazuhIndexerCollector(self.config, self.opener).collect(START, END))
        self.assertTrue(response.closed)

    def test_malformed_json_is_sanitized(self):
        for raw in [b'{"synthetic-private-marker":', b'{"x":NaN}', b'{"x":1,"x":2}', b'\xff']:
            self.opener.side_effect = [Response(raw)]
            try:
                list(WazuhIndexerCollector(self.config, self.opener).collect(START, END))
            except CollectorError:
                self.assertNotIn("synthetic-private-marker", traceback.format_exc())
            else:
                self.fail("Malformed input was accepted")

    def test_transient_errors_retry_with_bounded_backoff(self):
        self.opener.side_effect = responses(OSError("synthetic-private-marker"),
                                            HTTPError(ORIGIN, 503, "synthetic", {}, io.BytesIO()),
                                            created(), page([]), deleted())
        self.assertEqual(list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END)), [])
        self.assertEqual([x.args[0] for x in self.sleeper.call_args_list], [1, 2])

    def test_exhausted_retries_hide_transport_details(self):
        self.opener.side_effect = OSError("synthetic-private-marker")
        try:
            list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
        except CollectorError:
            self.assertNotIn("synthetic-private-marker", traceback.format_exc())
        else:
            self.fail("Transport error was accepted")
        self.assertEqual(self.opener.call_count, 3)

    def test_truncated_response_is_retried_and_sanitized(self):
        self.opener.side_effect = IncompleteRead(b"synthetic-private-marker")
        try:
            list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
        except CollectorError:
            self.assertNotIn("synthetic-private-marker", traceback.format_exc())
        else:
            self.fail("Truncated response was accepted")
        self.assertEqual(self.opener.call_count, 3)

    def test_permanent_http_errors_are_not_retried(self):
        for code in [301, 302, 307, 308, 400, 401, 403, 404]:
            self.opener.reset_mock()
            self.opener.side_effect = HTTPError(ORIGIN, code, "synthetic", {}, io.BytesIO())
            with self.assertRaises(CollectorError):
                list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
            self.assertEqual(self.opener.call_count, 1)

    def test_tls_and_redirect_protection(self):
        with patch("soc_thief.collector.build_opener") as build:
            WazuhIndexerCollector(self.config)
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(h, _NoRedirect) for h in handlers))
        self.assertEqual(next(h for h in handlers if isinstance(h, ProxyHandler)).proxies, {})
        context = next(h for h in handlers if isinstance(h, HTTPSHandler))._context
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        response = Mock()
        with self.assertRaises(CollectorError):
            _NoRedirect().redirect_request(None, response, 302, "synthetic", {}, ORIGIN)
        response.close.assert_called_once()

    def test_invalid_ca_and_certificate_errors_are_sanitized(self):
        ca = self.secret("synthetic-ca", "synthetic-private-marker")
        config = CollectorConfig(ORIGIN, self.user, self.password, ca_file=ca)
        try:
            WazuhIndexerCollector(config)
        except CollectorError:
            self.assertNotIn(str(ca), traceback.format_exc())
            self.assertNotIn("synthetic-private-marker", traceback.format_exc())
        else:
            self.fail("Invalid trust bundle accepted")
        self.opener.side_effect = ssl.SSLCertVerificationError("synthetic-private-marker")
        with self.assertRaises(CollectorError):
            list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
        self.assertEqual(self.opener.call_count, 1)

    def requests(self):
        return [call.args[0] for call in self.opener.call_args_list]

    def test_snapshot_lifecycle_uses_one_point_in_time(self):
        records = self.collect(page([hit()], 2), page([hit("synthetic-2")], 2))
        self.assertEqual(len(records), 2)
        create, first, second, delete = self.requests()
        self.assertEqual((create.method, create.data), ("POST", None))
        self.assertEqual(
            create.full_url,
            ORIGIN + "/wazuh-alerts-*-2026.01.01/_search/point_in_time?keep_alive=2m"
            "&allow_partial_pit_creation=false&allow_no_indices=false&ignore_unavailable=false",
        )
        for search in (first, second):
            self.assertEqual(search.method, "POST")
            self.assertEqual(search.full_url, ORIGIN + "/_search?allow_partial_search_results=false")
            payload = json.loads(search.data)
            self.assertEqual(payload["pit"], {"id": PIT, "keep_alive": "2m"})
            self.assertTrue(payload["track_total_hits"])
            self.assertEqual(payload["sort"], [{"@timestamp": {"order": "asc"}}, {"_index": "asc"}, {"_id": "asc"}])
        self.assertEqual(delete.method, "DELETE")
        self.assertEqual(delete.full_url, ORIGIN + "/_search/point_in_time")
        self.assertEqual(json.loads(delete.data), {"pit_id": [PIT]})

    def test_invalid_snapshot_creation_fails_before_search(self):
        cases = [None, [], {"_shards": created()["_shards"]}, {**created(), "error": "synthetic"}]
        for value in [None, "", 7, "x" * 65537, "synthetic\nmarker", "synthetic marker"]:
            cases.append(created(value))
        for key, value in [("failed", 1), ("successful", 1), ("total", 0), ("total", True)]:
            bad = created(); bad["_shards"][key] = value; cases.append(bad)
        bad = created(); del bad["_shards"]; cases.append(bad)
        for i, bad in enumerate(cases):
            self.opener.reset_mock()
            self.opener.side_effect = responses(bad, page([]), deleted())
            with self.subTest(case=i), self.assertRaises(CollectorError):
                list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
            self.assertEqual(self.opener.call_count, 1)

    def test_snapshot_identity_must_not_change(self):
        same = page([hit()], 2); same["pit_id"] = PIT
        other = page([hit("synthetic-2")], 2); other["pit_id"] = "synthetic-other-pit"
        with self.assertRaises(CollectorError):
            self.collect(same, other)
        self.assertEqual(self.requests()[-1].method, "DELETE")
        self.assertEqual(json.loads(self.requests()[-1].data), {"pit_id": [PIT]})
        unchanged = page([hit("synthetic-2")], 2); unchanged["pit_id"] = PIT
        self.assertEqual(len(self.collect(same, unchanged)), 2)

    def test_failure_releases_snapshot_without_masking_original_error(self):
        self.opener.side_effect = responses(created(), page([hit()], 2), page([], 1), OSError("synthetic-private-marker"))
        with self.assertRaisesRegex(CollectorError, "changed"):
            list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
        self.assertEqual(self.requests()[-1].method, "DELETE")
        self.assertEqual(self.opener.call_count, 4)

    def test_release_failure_after_complete_collection_fails_closed_once(self):
        config = CollectorConfig(ORIGIN, self.user, self.password, page_size=1, max_attempts=3)
        failures = [deleted(successful=False), deleted("synthetic-other-pit"), {"pits": []},
                    {"pits": [deleted()["pits"][0]] * 2}, None, OSError("synthetic-private-marker"),
                    HTTPError(ORIGIN, 503, "synthetic", {}, io.BytesIO())]
        for i, failure in enumerate(failures):
            self.opener.reset_mock()
            self.opener.side_effect = responses(created(), page([hit()]), failure)
            with self.subTest(case=i):
                try:
                    list(WazuhIndexerCollector(config, self.opener, self.sleeper).collect(START, END))
                except CollectorError as exc:
                    self.assertIn("release", str(exc))
                    self.assertNotIn(PIT, traceback.format_exc())
                    self.assertNotIn("synthetic-private-marker", traceback.format_exc())
                else:
                    self.fail("Unreleased snapshot was accepted")
                self.assertEqual(self.opener.call_count, 3)

    def test_abandoned_collection_releases_snapshot(self):
        iterator = self.collector(page([hit()], 2), page([hit("synthetic-2")], 2)).collect(START, END)
        next(iterator)
        iterator.close()
        self.assertEqual(self.requests()[-1].method, "DELETE")

    def test_search_retry_does_not_duplicate_records(self):
        self.opener.side_effect = responses(created(), page([hit()], 2), OSError("synthetic"),
                                            page([hit("synthetic-2")], 2), deleted())
        records = list(WazuhIndexerCollector(self.config, self.opener, self.sleeper).collect(START, END))
        self.assertEqual([r["source_key"]["id"] for r in records], ["synthetic-1", "synthetic-2"])
        self.assertEqual([x.args[0] for x in self.sleeper.call_args_list], [1])

    # --- PIT narrowed to the window's own UTC daily indices ---------------------------

    @staticmethod
    def _expected_utc_dates(start, end):
        """Independently computed (not via collector internals): every UTC calendar date the
        half-open window [start, end) touches, as YYYY.MM.DD strings."""
        first = start.astimezone(timezone.utc).date()
        last = (end.astimezone(timezone.utc) - timedelta(microseconds=1)).date()
        dates = []
        cursor = first
        while cursor <= last:
            dates.append(cursor.strftime("%Y.%m.%d"))
            cursor += timedelta(days=1)
        return dates

    def test_sydney_window_spans_exactly_two_utc_dates_24_23_25_hours(self):
        tz = ZoneInfo("Australia/Sydney")
        # (year, month, day) of the Sydney 08:00 window start; 2026-10-03 is the 23-hour
        # spring-forward day and 2026-04-04 is the 25-hour fall-back day (verified against the
        # zoneinfo transition table for Australia/Sydney).
        cases = [(2026, 9, 20, "24h recent"), (2026, 10, 3, "23h spring-forward"),
                 (2026, 4, 4, "25h fall-back")]
        for year, month, day, label in cases:
            with self.subTest(label=label):
                start = datetime(year, month, day, 8, 0, tzinfo=tz)
                next_day = start.date() + timedelta(days=1)
                end = datetime(next_day.year, next_day.month, next_day.day, 8, 0, tzinfo=tz)
                expected = self._expected_utc_dates(start, end)
                self.assertEqual(len(expected), 2, "test setup: expected exactly two UTC dates")
                self.opener.reset_mock()
                self.opener.side_effect = responses(created(), page([]), deleted())
                collector = WazuhIndexerCollector(self.config, self.opener, self.sleeper)
                self.assertEqual(list(collector.collect(start, end)), [])
                create = self.opener.call_args_list[0].args[0]
                pattern = ",".join(f"wazuh-alerts-*-{d}" for d in expected)
                self.assertEqual(urlsplit(create.full_url).path, f"/{pattern}/_search/point_in_time")

    def test_window_exceeding_31_utc_dates_raises_without_network(self):
        huge_end = START + timedelta(days=32)
        collector = WazuhIndexerCollector(self.config, self.opener, self.sleeper)
        with self.assertRaises(CollectorError):
            list(collector.collect(START, huge_end))
        self.opener.assert_not_called()

    def test_safety_parameters_present_on_pit_creation_and_non_pit_search(self):
        self.assertEqual(self.collect(page([])), [])
        create = self.opener.call_args_list[0].args[0]
        create_query = urlsplit(create.full_url).query
        for param in ("keep_alive=2m", "allow_partial_pit_creation=false",
                      "allow_no_indices=false", "ignore_unavailable=false"):
            self.assertIn(param, create_query)

        self.opener.reset_mock()
        self.opener.side_effect = responses(page([]))
        verify_config = CollectorConfig(ORIGIN, self.user, self.password, page_size=1, max_attempts=1)
        collector = WazuhIndexerCollector(verify_config, self.opener, self.sleeper)
        self.assertIs(collector.verify_metadata(START, START + timedelta(minutes=15)), False)
        search = self.opener.call_args_list[0].args[0]
        search_query = urlsplit(search.full_url).query
        for param in ("allow_partial_search_results=false", "allow_no_indices=false",
                      "ignore_unavailable=false"):
            self.assertIn(param, search_query)
        self.assertEqual(urlsplit(search.full_url).path, "/wazuh-alerts-*-2026.01.01/_search")

    def test_event_whose_index_date_is_outside_the_window_is_rejected(self):
        # The index date (2026.06.06) does not match START/END's requested date (2026.01.01),
        # even though @timestamp (set by hit()) is still inside the window. This pins the
        # narrowing's safety argument: index membership is trusted only when it is
        # timestamp-derived, never on the strength of an in-window @timestamp alone.
        mismatched = hit(index="wazuh-alerts-synthetic-2026.06.06")
        with self.assertRaisesRegex(CollectorError, "index date"):
            self.collect(page([mismatched], 1))

    def test_private_file_configuration_and_repr(self):
        url_file = self.secret("endpoint", ORIGIN)
        env = {"WAZUH_INDEXER_URL_FILE": str(url_file), "WAZUH_INDEXER_USERNAME_FILE": str(self.user),
               "WAZUH_INDEXER_PASSWORD_FILE": str(self.password)}
        config = CollectorConfig.from_environment(env)
        self.assertEqual(config.indexer_url, ORIGIN)
        self.assertNotIn(ORIGIN, repr(config))
        self.assertNotIn(str(self.root), repr(config))
        for bad in [{}, {"WAZUH_INDEXER_URL": ORIGIN}, {**env, "WAZUH_INDEXER_PASSWORD_FILE": ""}]:
            with self.assertRaises(CollectorError):
                CollectorConfig.from_environment(bad)

    def test_invalid_configuration(self):
        for url in ["http://example.invalid", ORIGIN + "/path", ORIGIN + "?q=x", ORIGIN + "#x",
                    "https://user@example.invalid", "https://example.invalid:bad", "https://[bad", ORIGIN + "\n"]:
            with self.assertRaises(ValueError):
                CollectorConfig(url, self.user, self.password)
        for key in ["page_size", "max_attempts", "max_pages"]:
            for value in [0, True, 1.5, 10001]:
                with self.assertRaises(ValueError):
                    CollectorConfig(ORIGIN, self.user, self.password, **{key: value})

    def test_systemd_credential_mount_is_owner_controlled_only_when_read_only(self):
        # Measured: a LoadCredential file reaches the rootless container root-owned 0400
        # plus a user ACL, so it shows as 0440 and host root shows as the overflow uid 65534.
        import os, stat as st
        def info(mode, uid): return os.stat_result((st.S_IFREG | mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))
        def statvfs(flag): return Mock(return_value=Mock(f_flag=flag))
        ro, rw = statvfs(os.ST_RDONLY), statvfs(0)
        me = os.geteuid()
        with patch("os.fstatvfs", rw):
            self.assertTrue(owner_controlled(0, info(0o600, me)))
            self.assertTrue(owner_controlled(0, info(0o400, 0)))
            for mode, uid in [(0o440, 0), (0o440, 65534), (0o400, 65534), (0o640, me)]:
                self.assertFalse(owner_controlled(0, info(mode, uid)), (oct(mode), uid))
        with patch("os.fstatvfs", ro):
            for mode, uid in [(0o440, 0), (0o440, 65534), (0o400, 65534), (0o440, me)]:
                self.assertTrue(owner_controlled(0, info(mode, uid)), (oct(mode), uid))
            for mode in (0o460, 0o450, 0o444, 0o442, 0o441, 0o404):
                self.assertFalse(owner_controlled(0, info(mode, 65534)), oct(mode))
            self.assertFalse(owner_controlled(0, info(0o440, me + 1 if me + 1 != 65534 else me + 2)))
            self.assertFalse(owner_controlled(0, os.stat_result((st.S_IFIFO | 0o400, 0, 0, 1, me, 0, 0, 0, 0, 0))))
        self.password.write_text("synthetic"); self.password.chmod(0o440)
        with self.assertRaises(CollectorError): read_secret(self.password)
        with patch("os.fstatvfs", ro): self.assertEqual(read_secret(self.password), "synthetic")

    def test_secret_files_reject_unsafe_inputs_without_path_disclosure(self):
        self.assertEqual(read_secret(self.secret("spaces", " synthetic-value \n")), " synthetic-value ")
        for value in ["", "x" * 8193, "synthetic\nembedded", "synthetic\x00"]:
            self.password.write_text(value)
            with self.assertRaises(CollectorError):
                read_secret(self.password)
        self.password.write_text("synthetic")
        self.password.chmod(0o644)
        with self.assertRaises(CollectorError):
            read_secret(self.password)
        link = self.root / "link"; link.symlink_to(self.user)
        for path in [link, self.root, self.root / "synthetic-private-marker"]:
            try:
                read_secret(path)
            except CollectorError:
                self.assertNotIn(str(self.root), traceback.format_exc())
            else:
                self.fail("Unsafe file was accepted")


def liveness_response(buckets, total=None, **agents_extra):
    return {
        "timed_out": False, "_shards": {"total": 2, "successful": 2, "failed": 0},
        "hits": {"hits": [], "total": {"value": sum(b["doc_count"] for b in buckets) if total is None else total,
                                       "relation": "eq"}},
        "aggregations": {"agents": {"buckets": buckets, "sum_other_doc_count": 0,
                                    "doc_count_error_upper_bound": 0, **agents_extra}},
    }


def bucket(agent, at, count=3):
    return {"key": agent, "doc_count": count,
            "latest": {"value": at.timestamp() * 1000, "value_as_string": at.isoformat()}}


class AgentLastSeenTest(unittest.TestCase):
    """One aggregation-only read; every malformed or inconsistent answer fails closed."""
    setUp = CollectorTest.setUp
    secret = CollectorTest.secret
    LATE = END - timedelta(hours=1)

    def last_seen(self, response, ids=("001", "002")):
        self.opener.side_effect = responses(response)
        return WazuhIndexerCollector(self.config, self.opener).agent_last_seen(ids, START, END)

    def test_returns_latest_time_per_listed_agent_from_an_aggregation_only_query(self):
        seen = self.last_seen(liveness_response([bucket("001", self.LATE)]))
        self.assertEqual(seen, {"001": self.LATE})
        request = self.opener.call_args.args[0]
        self.assertIn("/wazuh-alerts-*-2026.01.01/_search?", request.full_url)
        payload = json.loads(request.data)
        self.assertEqual(payload["size"], 0)
        self.assertNotIn("_source", payload)
        self.assertEqual(payload["query"]["bool"]["filter"][1], {"terms": {"agent.id": ["001", "002"]}})
        self.assertEqual(payload["aggs"]["agents"]["terms"], {"field": "agent.id", "size": 2})
        self.assertEqual(payload["aggs"]["agents"]["aggs"], {"latest": {"max": {"field": "@timestamp"}}})

    def test_malformed_or_inconsistent_answers_fail_closed(self):
        bad = [
            liveness_response([bucket("003", self.LATE)]),
            liveness_response([bucket("001", self.LATE), bucket("001", self.LATE)]),
            liveness_response([bucket("001", self.LATE)], total=4),
            liveness_response([bucket("001", END)]),
            liveness_response([bucket("001", START - timedelta(seconds=1))]),
            liveness_response([bucket("001", self.LATE)], sum_other_doc_count=1),
            liveness_response([{**bucket("001", self.LATE), "latest": {"value": None}}]),
            liveness_response([{**bucket("001", self.LATE), "extra": 1}]),
            {**liveness_response([bucket("001", self.LATE)]), "timed_out": True},
            {**liveness_response([bucket("001", self.LATE)]), "hits": {"hits": [hit()], "total": {"value": 3, "relation": "eq"}}},
            {**liveness_response([]), "_shards": {"total": 2, "successful": 1, "failed": 1}},
        ]
        for response in bad:
            with self.subTest(response=response), self.assertRaises(CollectorError):
                self.last_seen(response)

    def test_invalid_queries_are_refused_before_any_request(self):
        collector = WazuhIndexerCollector(self.config, self.opener)
        for ids, start, end in [((), START, END), (("host-a",), START, END), (("001",), START, START),
                                (("001",), START, START + timedelta(days=8)),
                                (("001",), START.replace(tzinfo=None), END)]:
            with self.subTest(ids=ids, start=start, end=end), self.assertRaises(CollectorError):
                collector.agent_last_seen(ids, start, end)
        self.opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
