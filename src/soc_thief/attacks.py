"""Attack shots for the console's globe view: who hit us, from which country, and when.

    python -m soc_thief.attacks --snapshot snapshot.json --geoip dbip-country-lite.csv --home AU

Reads the snapshot's own window through the read-only collector, looks up each alert's
``data.srcip`` in an offline DB-IP Lite country CSV, and adds an ``attacks`` block to the
snapshot (docs/SNAPSHOT.md). The demo builds the same block from a seeded generator.

A shot keeps only a country code, a level, a kind and a sanitised rule description. No IP
address, host name or agent name goes into the snapshot. Tuning marks a shot ``tuned``, and a
breach signal marks it ``breach`` even when tuned, as in policy. Nothing here changes delivery.
"""

from __future__ import annotations

import argparse
import bisect
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
import gzip
import io
import ipaddress
import json
import os
from pathlib import Path
import random
import sys
from typing import Any, Iterable, Mapping

from soc_thief import breach
from soc_thief.delivery import _IPV4, _SECRET
from soc_thief.tuning import Tuning

KINDS = ("tuned", "reported", "breach")
LAN = "LAN"
MAX_SHOTS = 20_000          # docs/SNAPSHOT.md: at most this many shots are listed
MAX_RECORDS = 1_000_000     # a window bigger than this is refused rather than half-read
MAX_GEOIP_BYTES = 256 * 1024 * 1024
MAX_GEOIP_ROWS = 4_000_000
LABEL_LIMIT = 48


class AttacksError(RuntimeError):
    """A fixed-text failure; never carries alert content, paths or credentials."""


@dataclass(frozen=True)
class Shot:
    at: float              # seconds after the window start
    country: str | None    # ISO 3166-1 alpha-2, LAN, or None when there is no usable source
    level: int
    kind: str
    label: str


def label(value: object) -> str:
    if type(value) is not str:
        return "?"
    text = "".join(char if char.isprintable() else "?" for char in value)
    text = _IPV4.sub("[ip]", _SECRET.sub("[secret]", text)).strip() or "?"
    return text if len(text) <= LABEL_LIMIT else text[:LABEL_LIMIT - 1] + "…"


class GeoIP:
    """Offline country lookup from a DB-IP Lite country CSV (``start,end,country``), plain or gzip."""

    def __init__(self, rows: Iterable[tuple[str, str, str]]) -> None:
        tables: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
        for count, (start, end, code) in enumerate(rows):
            if count >= MAX_GEOIP_ROWS:
                raise AttacksError("GeoIP file has too many rows")
            try:
                first, last = ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
            except ValueError:
                raise AttacksError("GeoIP file is not a start,end,country CSV") from None
            code = code.strip().upper()
            if first.version != last.version or int(first) > int(last) or len(code) != 2 or not code.isalpha():
                raise AttacksError("GeoIP file is not a start,end,country CSV")
            tables[first.version].append((int(first), int(last), code))
        self._tables = {}
        for version, table in tables.items():
            table.sort()
            self._tables[version] = ([row[0] for row in table], [row[1] for row in table],
                                     [row[2] for row in table])

    @classmethod
    def load(cls, path: Path) -> GeoIP:
        try:
            if path.stat().st_size > MAX_GEOIP_BYTES:
                raise AttacksError("GeoIP file is too large")
            raw = path.read_bytes()
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
            if len(raw) > MAX_GEOIP_BYTES:
                raise AttacksError("GeoIP file is too large")
            return cls(row for row in csv.reader(io.StringIO(raw.decode("ascii"))) if row)
        except AttacksError:
            raise
        except (OSError, ValueError, csv.Error):
            raise AttacksError("GeoIP file could not be read") from None

    def country(self, value: object) -> str | None:
        """ISO alpha-2, LAN for a non-global address, or None when unknown or unparseable."""
        if type(value) is not str:
            return None
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        if not address.is_global:
            return LAN
        starts, ends, codes = self._tables[address.version]
        index = bisect.bisect_right(starts, int(address)) - 1
        if index < 0 or int(address) > ends[index] or codes[index] == "ZZ":
            return None
        return codes[index]


def shots_from_records(records: Iterable[Mapping], start: datetime, tuning: Tuning,
                       geoip: GeoIP) -> list[Shot]:
    """Allowlisted collector records -> shots, oldest first. Breach outranks tuning, as in policy."""
    pending, correlate = [], breach.BruteForceSuccess()
    for index, record in enumerate(records):
        if index >= MAX_RECORDS:
            raise AttacksError("the window has too many events for the globe")
        fields = record["fields"]
        stamp = datetime.fromisoformat(fields["@timestamp"].replace("Z", "+00:00"))
        correlate.observe(fields, stamp, index)
        if breach.event_signals(fields):
            kind = "breach"
        elif tuning.action(fields["rule.id"], fields["agent.id"], stamp) is not None:
            kind = "tuned"
        else:
            kind = "reported"
        level = fields["rule.level"] if type(fields["rule.level"]) is int else 0
        pending.append(((stamp - start).total_seconds(), geoip.country(fields.get("data.srcip")),
                        level, kind, label(fields["rule.description"])))
    flagged = correlate.flagged()
    shots = [Shot(at, country, level, "breach" if index in flagged else kind, text)
             for index, (at, country, level, kind, text) in enumerate(pending)]
    shots.sort(key=lambda shot: shot.at)
    return shots


def block(shots: list[Shot], *, home: str, start: str, end: str) -> dict[str, Any]:
    """The snapshot's ``attacks`` block. Shots with no source are counted, not listed.

    Over the cap, breach shots are kept first, then reported, then tuned, newest last.
    """
    if type(home) is not str or len(home) != 2 or not home.isalpha():
        raise AttacksError("--home must be a two-letter ISO country code")
    sourced = [shot for shot in shots if shot.country is not None]
    kept = sorted(sourced, key=lambda shot: (-KINDS.index(shot.kind), shot.at))[:MAX_SHOTS]
    kept.sort(key=lambda shot: shot.at)
    return {"home": home.upper(), "start": start, "end": end,
            "no_source": len(shots) - len(sourced), "dropped": len(sourced) - len(kept),
            "shots": [{"t": round(shot.at, 1), "country": shot.country, "level": shot.level,
                       "kind": shot.kind, "label": shot.label} for shot in kept]}


# ---- demo --------------------------------------------------------------------------------

DEMO_HOME = "AU"
_DEMO_COUNTRIES = ("CN", "US", "RU", "NL", "DE", "BR", "IN", "VN", "KR", "GB", "FR", "SG",
                   "ID", "IR", "UA", "RO", "HK", "TW", "JP", "ZA", "AR", "TR", "CA", "SE")
_DEMO_RULES = (
    ("tuned", 5, "sshd: authentication failed."),
    ("tuned", 6, "Web server 400 error code."),
    ("tuned", 3, "Firewall drop event."),
    ("tuned", 5, "PAM: User login failed."),
    ("reported", 10, "sshd: brute force trying to get access to the system."),
    ("reported", 6, "Multiple web server 400 error codes from same source ip."),
    ("reported", 7, "Possible port scan detected."),
    ("reported", 12, "SQL injection attempt."),
)


def demo_shots(seconds: float, breaches: Iterable[tuple[float, str]] = (), *, seed: int,
               rate: float = 0.17) -> list[Shot]:
    """Seeded synthetic attacks across ``seconds``, plus one breach shot per ``(at, name)``."""
    rng = random.Random(f"attacks-{seed}")
    weights = [1 / (rank + 1) for rank in range(len(_DEMO_COUNTRIES))]
    shots, at = [], 0.0
    while True:
        at += rng.expovariate(rate)
        if at >= seconds:
            break
        kind, level, text = (_DEMO_RULES[rng.randrange(4)] if rng.random() < 0.85
                             else rng.choice(_DEMO_RULES[4:]))
        country = LAN if rng.random() < 0.03 else rng.choices(_DEMO_COUNTRIES, weights)[0]
        shots.append(Shot(at, country, level, kind, label(text)))
    for at, name in breaches:
        shots.append(Shot(at, rng.choice(_DEMO_COUNTRIES[:6]), 12, "breach", label(name)))
    shots.sort(key=lambda shot: shot.at)
    return shots


# ---- live --------------------------------------------------------------------------------

def collect(start: datetime, end: datetime, geoip: GeoIP, env: Mapping[str, str],
            collector_factory=None) -> list[Shot]:
    """One read-only pass over the window. Needs the collector's ``WAZUH_INDEXER_*_FILE`` settings."""
    from soc_thief.collector import CollectorConfig, CollectorError, WazuhIndexerCollector
    from soc_thief.tuning import TuningError, load_tuning
    try:
        tuning = load_tuning(env)
    except TuningError:
        raise AttacksError("the tuning file could not be loaded") from None
    try:
        collector = (collector_factory or WazuhIndexerCollector)(CollectorConfig.from_environment(env))
        return shots_from_records(collector.collect(start, end), start, tuning, geoip)
    except CollectorError:
        raise AttacksError("collection failed; check the WAZUH_INDEXER_*_FILE settings") from None


def _window(snapshot: Mapping[str, Any]) -> tuple[datetime, datetime, str, str]:
    try:
        first, last = snapshot["window"]["start"], snapshot["window"]["end"]
        start, end = datetime.fromisoformat(first), datetime.fromisoformat(last)
    except (KeyError, TypeError, ValueError):
        raise AttacksError("the snapshot has no usable window") from None
    if start.utcoffset() is None or not start < end or end - start > timedelta(days=2):
        raise AttacksError("the snapshot has no usable window")
    return start, end, first, last


def main(argv: list[str] | None = None, *, collector_factory=None) -> int:
    from soc_thief.demo import write_json
    parser = argparse.ArgumentParser(description="Add the globe's attack shots to a snapshot, read-only.")
    parser.add_argument("--snapshot", required=True, help="Snapshot JSON to add the attacks block to")
    parser.add_argument("--geoip", required=True, type=Path, help="DB-IP Lite country CSV, plain or .gz")
    parser.add_argument("--home", required=True, help="Two-letter country code the arcs land on")
    args = parser.parse_args(argv)
    try:
        try:
            snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise AttacksError("the snapshot could not be read") from None
        start, end, first, last = _window(snapshot)
        geoip = GeoIP.load(args.geoip)
        print("Collecting the snapshot's window (read-only)...", file=sys.stderr)
        shots = collect(start, end, geoip, os.environ, collector_factory)
        snapshot["attacks"] = block(shots, home=args.home, start=first, end=last)
        write_json(args.snapshot, snapshot)
    except AttacksError as error:
        print(f"Attacks failed: {error}.", file=sys.stderr)
        return 2
    except Exception:
        # Paths, credentials and alert fields must not surface through a traceback.
        print("Attacks failed; no alert content was printed.", file=sys.stderr)
        return 2
    attacks = snapshot["attacks"]
    print(f"Attacks added: {len(attacks['shots'])} shots, {attacks['dropped']} over the cap, "
          f"{attacks['no_source']} with no source address.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
