"""Bounded noise-profile report for operator tuning; writes only a new private output file.

Stdout carries fixed status text and integer totals only. Rule descriptions, agent names, and
identifiers appear only in the report file, sanitised. Nothing is muted or configured here.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import stat
import string
import unicodedata
from datetime import datetime, timezone
from typing import Any, Callable

from soc_thief.zone import check as check_zone, name as report_zone_name
from soc_thief.collector import CollectorConfig, WazuhIndexerCollector, check_profile_window
from soc_thief.policy import preflight

DEADLINE_SECONDS = 180
LABEL_LIMIT = 120
_MESSAGES = {
    1: "Noise profile failed; review required. Details withheld.",
    3: "Noise profile deadline exceeded; review required.",
}
_SUCCESS = "Noise profile written: {} groups, {} events. Review before writing tuning rules."
_SUCCESS_PROPOSAL_SUFFIX = (" Tuning proposal written to a separate file for operator review; "
                            "it is not installed and nothing is muted automatically.")
_INVALID_ARGS = "Invalid noise profile arguments; use --help."
_INVALID_WINDOW = "Invalid noise profile window; use aware, closed timestamps at most 120 days apart."
_INVALID_OUTPUT = "Invalid output path; use a new file in an existing private directory you own."
_OUTPUT_ERROR = "output must be a new file in a private owner-controlled directory"
_COLUMNS = ("rank", "events", "share %", "cumulative %", "days active", "max level",
            "rule_id", "agent_id", "rule description", "agent name", "tunable")


class OutputError(RuntimeError):
    """The output path is unsafe or could not be created; text never includes the path."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally repeats untrusted argument text in its diagnostics.
        self.exit(2, _INVALID_ARGS + "\n")


def _open_parent(raw: str) -> tuple[int, str]:
    name, parent = os.path.basename(raw), os.path.dirname(raw) or "."
    if name in ("", ".", "..") or "\x00" in raw:
        raise OutputError(_OUTPUT_ERROR)
    try:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, ValueError):
        raise OutputError(_OUTPUT_ERROR) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise OutputError(_OUTPUT_ERROR)
    except BaseException:
        os.close(fd)
        raise
    return fd, name


def check_output(raw: str) -> None:
    """Fail early unless the parent is private and owned and the final name does not exist."""
    fd, name = _open_parent(raw)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise OutputError(_OUTPUT_ERROR) from None
    finally:
        os.close(fd)
    raise OutputError(_OUTPUT_ERROR)


def write_private(raw: str, text: str) -> None:
    """Create the report exclusively, mode 0600, never following or replacing a final link."""
    data = text.encode("utf-8")
    dir_fd, name = _open_parent(raw)
    try:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dir_fd)
        except OSError:
            raise OutputError(_OUTPUT_ERROR) from None
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        except OSError:
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError:
                pass
            raise OutputError(_OUTPUT_ERROR) from None
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


def _label(value: str | None, complete: bool = True, limit: int = LABEL_LIMIT) -> str:
    """Neutralise terminal controls and Markdown/mention syntax, then cap the visible length."""
    if value is None:
        return "(missing)"
    characters = []
    for character in value:
        category = unicodedata.category(character)
        if category == "Zs":
            characters.append(" ")
        elif category[0] in "CZ":
            characters.append("?")
        else:
            characters.append(character)
    text = "".join(characters)
    truncated = len(text) > limit
    escaped = "".join("(at)" if c == "@" else "\\" + c if c in string.punctuation else c
                      for c in text[:limit])
    return escaped + ("..." if truncated else "") + ("" if complete else " (+variants)")


def _candidate(row: dict[str, Any]) -> str:
    line = json.dumps({"rule_id": row["rule_id"], "agent_id": row["agent_id"]}, ensure_ascii=True)
    # JSON-equivalent escapes keep the fence, mentions, and DEL inert.
    return line.replace("`", "\\u0060").replace("@", "\\u0040").replace("\x7f", "\\u007f")


def tunable(row: dict[str, Any], end: datetime) -> str:
    """Reuse delivery policy: protected rows are never tuning candidates."""
    if row["rule_description"] is None or not row["description_complete"]:
        return "no (review)"
    decision = preflight({
        "timestamp": end.astimezone(timezone.utc).isoformat(), "rule_id": row["rule_id"],
        "rule_level": row["max_level"], "rule_description": row["rule_description"],
        "agent_id": row["agent_id"], "count": row["events"],
    })
    if decision.health_failure:
        return "no (review)"
    return "no (protected)" if decision.delivery_required else "yes"


def render_report(start: datetime, end: datetime, profile: dict[str, Any]) -> str:
    total = profile["total"]
    rows = sorted(profile["groups"], key=lambda r: (-r["events"], r["rule_id"], r["agent_id"]))
    verdicts = [tunable(row, end) for row in rows]
    lines = [
        "# Soc Thief noise profile",
        "",
        f"- Window (UTC): {start.astimezone(timezone.utc).isoformat()} to "
        f"{end.astimezone(timezone.utc).isoformat()} (start inclusive, end exclusive)",
        f"- Total events: {total}",
        f"- Groups (rule_id, agent_id): {len(rows)}",
        f"- Tunable groups: {verdicts.count('yes')}; not tunable: {len(rows) - verdicts.count('yes')}",
        f"- Days active counts {report_zone_name()} calendar days with at least one event.",
        f"- Labels show the most frequent value, sanitised and capped at {LABEL_LIMIT} characters; "
        "(+variants) means one value does not cover every event.",
        "- Tunable: no (protected) = level 12+ or protected policy vocabulary; "
        "no (review) = labels missing, varied, or invalid.",
        "",
        "| " + " | ".join(_COLUMNS) + " |",
        "| " + " | ".join("---:" if i < 6 else "---" for i in range(len(_COLUMNS))) + " |",
    ]
    cumulative = 0
    candidates = []
    for rank, (row, verdict) in enumerate(zip(rows, verdicts), start=1):
        if verdict == "yes" and cumulative * 5 < total * 4:
            candidates.append(_candidate(row))
        cumulative += row["events"]
        cells = [
            str(rank), str(row["events"]), f"{row['events'] * 100 / total:.2f}",
            f"{cumulative * 100 / total:.2f}", str(row["days_active"]), str(row["max_level"]),
            _label(row["rule_id"]), _label(row["agent_id"]),
            _label(row["rule_description"], row["description_complete"]),
            _label(row["agent_name"], row["agent_name_complete"]), verdict,
        ]
        lines.append("| " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Top candidates",
        "",
        "Candidates for operator review only, not recommendations to mute: tunable groups that "
        "begin within the first 80% of event volume.",
        "",
        "```",
        *(candidates or ["(none)"]),
        "```",
        "",
        "---",
        "",
        "Tuning entries must be written and reviewed by the operator. Nothing is muted "
        "automatically; this report changes no Wazuh or Soc Thief configuration.",
        "",
    ]
    return "\n".join(lines)


def _worker(start: datetime, end: datetime, output: str, conn: Any,
            propose_tuning: str | None = None) -> None:
    code = 1
    try:
        profile = WazuhIndexerCollector(CollectorConfig.from_environment()).profile(start, end)
        write_private(output, render_report(start, end, profile))
        if propose_tuning is not None:
            # Imported here, not at module load: soc_thief.baseline imports `tunable` from this
            # module, so importing it at module scope would be a circular import.
            from soc_thief import baseline
            window_days = max(1, (end - start).days)
            proposals = baseline.propose(profile["groups"], end=end, window_days=window_days)
            write_private(propose_tuning, json.dumps(baseline.serialize(proposals), indent=2))
        conn.send((len(profile["groups"]), profile["total"]))
        code = 0
    except Exception:
        # Never expose configuration, labels, paths, or response tracebacks.
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    raise SystemExit(code)


def _run_worker(start: datetime, end: datetime, output: str, propose_tuning: str | None = None, *,
                timeout: float = DEADLINE_SECONDS,
                target: Callable = _worker) -> tuple[int, tuple[int, int] | None]:
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(start, end, output, writer, propose_tuning))
    try:
        process.start()
        writer.close()
        process.join(timeout)
        if process.is_alive():
            return 3, None
        if process.exitcode != 0 or not reader.poll(1):
            return 1, None
        counts = reader.recv()
        if (type(counts) is tuple and len(counts) == 2
                and all(type(value) is int and value >= 0 for value in counts)):
            return 0, counts
        return 1, None
    except Exception:
        return 1, None
    finally:
        reader.close()
        writer.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
                process.join(5)
            if not process.is_alive():
                process.close()


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="Write a bounded, aggregation-only noise profile to a private file.")
    parser.add_argument("--start", required=True, help="Timezone-aware ISO timestamp (inclusive)")
    parser.add_argument("--end", required=True, help="Timezone-aware ISO timestamp (exclusive, in the past)")
    parser.add_argument("--output", required=True, help="New report path in a private directory you own")
    parser.add_argument("--propose-tuning", dest="propose_tuning", default=None,
                        help="Optional new path for a tuning-file-shaped proposal, for operator "
                             "review only; never installed automatically")
    args = parser.parse_args(argv)
    problem = check_zone()
    if problem:
        print(problem)
        return 2
    try:
        start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
        check_profile_window(start, end)
    except ValueError:
        print(_INVALID_WINDOW)
        return 2
    try:
        check_output(args.output)
        if args.propose_tuning is not None:
            if args.propose_tuning == args.output:
                raise OutputError(_OUTPUT_ERROR)
            check_output(args.propose_tuning)
    except OutputError:
        print(_INVALID_OUTPUT)
        return 2
    code, counts = _run_worker(start, end, args.output, args.propose_tuning)
    message = _SUCCESS.format(*counts) if code == 0 and counts else _MESSAGES[3 if code == 3 else 1]
    if code == 0 and counts and args.propose_tuning is not None:
        message += _SUCCESS_PROPOSAL_SUFFIX
    print(message)
    return code if code in (0, 3) else 1


if __name__ == "__main__":
    raise SystemExit(main())
