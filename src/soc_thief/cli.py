"""soc-thief: an agent-facing, read-only CLI over a Soc Thief snapshot.

It follows AXI (github.com/kunchenguid/axi): TOON on stdout, live content with no arguments,
small default schemas, truncation with size hints, errors on stdout, exit 2 for usage errors,
and no prompts. Every answer comes from ``soc_thief.query``; this module only parses
arguments and formats. Nothing here can change delivery, tuning or state.

Exit codes: 0 ok, 1 failed (no snapshot, bad snapshot, unknown group, generation failed),
2 usage error.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import re
import shlex
import sys
from typing import Any, Callable

VERSION_FLAGS = ("-v", "-V", "--version")
EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2
DESCRIPTION = "Read-only view of Soc Thief's latest Wazuh triage snapshot: alert groups, health and breach pages"
SNAPSHOT_ENV = "SOC_THIEF_SNAPSHOT"
DEFAULT_SNAPSHOT = "snapshot.json"
LIST_TEXT = 100
DETAIL_TEXT = 500
CHECK_TEXT = 200
AGENTS_SHOWN = 10
TOP_GROUPS = 5
ADVISORY = "advisory only: policy and operator tuning decide delivery; the model cannot suppress anything"

# Extra columns `groups --fields` can add after id,category,level,rule.
GROUP_FIELDS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "count": lambda g: g["count"],
    "rule_id": lambda g: g["rule_id"],
    "agents": lambda g: " ".join(g["agents"]),
    "protected": lambda g: g["protected"],
    "tuning": lambda g: g["tuning"],
    "delivery_required": lambda g: g["decision"]["delivery_required"],
    "reason": lambda g: g["decision"]["reason"],
    "first_seen": lambda g: g["first_seen"],
    "last_seen": lambda g: g["last_seen"],
    "advisory_verdict": lambda g: g["model"]["verdict"] if g["model"] else None,
    "advisory_confidence": lambda g: g["model"]["confidence"] if g["model"] else None,
}
_TRUNCATED_FIELDS = ("agents",)

GLOBAL_FLAGS = ("--snapshot", "--json", "--full", "--help")

# name -> (usage, description, own flags as (flag, default, meaning), examples)
COMMANDS: dict[str, tuple[str, str, list[tuple[str, str, str]], list[str]]] = {
    "status": ("soc-thief status", "The overview the bare command shows, without the tool header.", [],
               ["soc-thief status", "soc-thief status --json"]),
    "groups": ("soc-thief groups [--category C] [--filter TEXT] [--limit N] [--fields F,...]",
               "Alert groups in digest order: failed, new, spike, recurring; then level and count, high first.",
               [("--category C", "all", "failed, new, spike or recurring"),
                ("--filter TEXT", "none", "case-insensitive match on id, rule id, rule text and agent names"),
                ("--limit N", "100", "rows to show; the total is always printed"),
                ("--fields F,...", "none", "extra columns: " + ",".join(GROUP_FIELDS))],
               ["soc-thief groups --category new", "soc-thief groups --filter sshd --fields count,agents",
                "soc-thief groups --limit 500 --full"]),
    "group": ("soc-thief group ID", "One group in full: rule, agents, decision and the model's advisory verdict.", [],
              ["soc-thief group g-8b3d7a66a966", "soc-thief group g-8b3d7a66a966 --full"]),
    "breaches": ("soc-thief breaches", "Breach detections in the window and whether each one paged.", [],
                 ["soc-thief breaches"]),
    "health": ("soc-thief health", "Every health check and its status.", [], ["soc-thief health"]),
    "history": ("soc-thief history", "Earlier windows, newest first: events, delivery and health failures.", [],
                ["soc-thief history"]),
    "demo": ("soc-thief demo [--out PATH] [--seed N] [--now TIME]",
             "Write a demo snapshot: synthetic alerts through the real grouping, policy and digest code. "
             "No network, nothing sent.",
             [("--out PATH", "the --snapshot path", "where to write"),
              ("--seed N", "7", "generator seed"),
              ("--now TIME", "now", "ISO time with offset to run as")],
             ["soc-thief demo", "soc-thief demo --out /tmp/demo.json --now 2026-11-07T08:00:04+11:00"]),
    "snapshot": ("soc-thief snapshot --state DIR [--out PATH]",
                 "Write a snapshot from a deployment's state store, read-only.",
                 [("--state DIR", "required", "state directory or its state.sqlite3"),
                  ("--out PATH", "the --snapshot path", "where to write")],
                 ["soc-thief snapshot --state /var/lib/soc-thief"]),
}
_GLOBAL_HELP = [
    ("--snapshot PATH", f"${SNAPSHOT_ENV}, else ./{DEFAULT_SNAPSHOT}", "snapshot file to read"),
    ("--json", "off", "print the query result as JSON instead of TOON"),
    ("--full", "off", "do not truncate long text"),
    ("--help", "", "this command's usage"),
]


class Usage(Exception):
    def __init__(self, message: str, command: str | None) -> None:
        super().__init__(message)
        self.command = command


class Failure(Exception):
    def __init__(self, message: str, hints: list[str]) -> None:
        super().__init__(message)
        self.hints = hints


class _Parser(argparse.ArgumentParser):
    command: str | None = None

    def error(self, message: str) -> None:  # type: ignore[override]
        match = re.match(r"argument command: invalid choice: '(.*)' \(choose from", message)
        if match:
            message = f"unknown command {match.group(1)}; commands: {', '.join(COMMANDS)}"
        raise Usage(message, self.command)


def version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version as dist_version
        return dist_version("soc-thief")
    except (ImportError, PackageNotFoundError):
        from soc_thief import __version__
        return __version__


# --- argument parsing -------------------------------------------------------------------


def _add_globals(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--snapshot", default=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--full", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true", default=argparse.SUPPRESS)


def _limit(value: str) -> int:
    number = int(value)
    if number < 1:
        raise ValueError
    return number


_limit.__name__ = "positive integer"  # argparse names the type in its error message.


def build_parser() -> _Parser:
    parser = _Parser(prog="soc-thief", add_help=False, allow_abbrev=False)
    _add_globals(parser)
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)
    for name in COMMANDS:
        child = sub.add_parser(name, add_help=False, allow_abbrev=False)
        child.command = name
        _add_globals(child)
        if name == "groups":
            child.add_argument("--category", choices=("failed", "new", "spike", "recurring"))
            child.add_argument("--filter")
            child.add_argument("--limit", type=_limit, default=100)
            child.add_argument("--fields")
        elif name == "group":
            child.add_argument("id", nargs="?")
        elif name == "demo":
            child.add_argument("--out")
            child.add_argument("--seed", type=int)
            child.add_argument("--now")
        elif name == "snapshot":
            child.add_argument("--state")
            child.add_argument("--out")
    return parser


def _flags_for(command: str | None) -> list[str]:
    own = [flag.split()[0] for flag, _, _ in COMMANDS[command][2]] if command else []
    return own + list(GLOBAL_FLAGS)


def parse(argv: list[str]) -> argparse.Namespace:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    command = getattr(args, "command", None)
    if extra:
        first = extra[0]
        if first.startswith("-"):
            where = f" for {command}" if command else ""
            raise Usage(f"unknown flag {first.split('=')[0]}{where}", command)
        raise Usage(f"unexpected argument {first}", command)
    if command == "group" and not args.id and not getattr(args, "help", False):
        raise Usage("group needs an ID", command)
    if command == "snapshot" and not args.state and not getattr(args, "help", False):
        raise Usage("snapshot needs --state DIR", command)
    return args


# --- formatting helpers -----------------------------------------------------------------


class Context:
    """Formatting state for one command.

    The phrasing methods (``run``, ``full_hint``, ``fields_hint``, ``load_hints``) are the only
    shell-specific text. Another front end, such as the MCP server, subclasses this and
    overrides them, so the same views name that front end's next step.
    """

    def __init__(self, args: argparse.Namespace, environ: dict[str, str]) -> None:
        explicit = getattr(args, "snapshot", None)
        self.snapshot_path = explicit or environ.get(SNAPSHOT_ENV) or DEFAULT_SNAPSHOT
        self.full = bool(getattr(args, "full", False))
        self.json = bool(getattr(args, "json", False))
        # Suggestions carry the --snapshot flag forward when it was given on the command line.
        self.prefix = "soc-thief" + (f" --snapshot {shlex.quote(_clean(explicit))}" if explicit else "")
        self.truncated = False

    def run(self, rest: str) -> str:
        """A next-step phrase for a command fragment such as ``groups --category new``."""
        return f"Run `{self.prefix} {rest}`"

    def full_hint(self) -> str:
        return "Add `--full` to see text that was cut"

    def fields_hint(self) -> str:
        return "Add `--fields count,agents,delivery_required` for more columns"

    def load_hints(self) -> list[str]:
        return [f"{self.run('demo')} to write a demo snapshot to {shlex.quote(_clean(self.snapshot_path))}",
                f"Run `soc-thief --snapshot <path>` to read another file, or set ${SNAPSHOT_ENV}"]

    def clip(self, text: str, limit: int) -> str:
        if self.full or len(text) <= limit:
            return text
        self.truncated = True
        return f"{text[:limit]}…(+{len(text) - limit} chars)"


def _clean(text: str) -> str:
    from soc_thief.query import clean_text
    return clean_text(text)


def _home_path(path: str) -> str:
    home = os.path.expanduser("~")
    if home and home != "/" and (path == home or path.startswith(home + os.sep)):
        return "~" + path[len(home):]
    return path


def _bin() -> str:
    argv0 = sys.argv[0] if sys.argv and sys.argv[0] else ""
    if not argv0 or argv0.endswith(("__main__.py", "-c")) or os.path.basename(argv0).startswith("python"):
        return "python3 -m soc_thief"
    return _home_path(os.path.abspath(argv0))


def _rule(group: dict[str, Any]) -> str:
    return group["rule_description"] or (f"rule {group['rule_id']}" if group["rule_id"] else "")


def _row(group: dict[str, Any], ctx: Context, extra: list[str] = ()) -> dict[str, Any]:  # type: ignore[assignment]
    row: dict[str, Any] = {"id": group["id"], "category": group["category"], "level": group["level"],
                           "rule": ctx.clip(_rule(group), LIST_TEXT)}
    for name in extra:
        value = GROUP_FIELDS[name](group)
        row[name] = ctx.clip(value, LIST_TEXT) if name in _TRUNCATED_FIELDS else value
    return row


def render(document: dict[str, Any], hints: list[str] = ()) -> str:  # type: ignore[assignment]
    """TOON text for a view, with its help block when there are hints."""
    from soc_thief import toon
    text = toon.encode(document)
    block = toon.help_block(hints)
    return text + ("\n" + block if block else "")


def _emit(document: dict[str, Any], hints: list[str] = ()) -> None:  # type: ignore[assignment]
    print(render(document, hints))


def _emit_json(document: Any) -> None:
    print(json.dumps(document, indent=1, ensure_ascii=True))


# --- views ------------------------------------------------------------------------------
# Each view turns a soc_thief.query result into the TOON document and hints. The commands
# below print them; the MCP server returns them. Views read nothing and change nothing.

View = tuple[dict[str, Any], list[str]]


def overview_view(ctx: Context, result: dict[str, Any], *, header: bool) -> View:
    doc: dict[str, Any] = {}
    if header:
        doc["bin"] = _bin()
        doc["description"] = DESCRIPTION
    doc["snapshot"] = _clean(ctx.snapshot_path)
    doc["source"] = result["source"]
    if result["source"] == "demo":
        doc["note"] = "demo data: generated alerts run through the real pipeline; nothing was sent"
    doc["generated_at"] = result["generated_at"]
    doc["window"] = result["window"]
    doc["health"] = result["health"]["status"]
    if result["health"]["not_ok"]:
        doc["checks_not_ok"] = [{"name": c["name"], "status": c["status"], "detail": ctx.clip(c["detail"], CHECK_TEXT)}
                                for c in result["health"]["not_ok"]]
    window_groups = result["window"]["groups"]
    doc["groups"] = {
        "listed": f"{result['listed_groups']} of {window_groups}",
        **result["categories"],
        "delivery_required": result["delivery_required"],
        "protected": result["protected"],
        "health_failures": result["group_health_failures"],
    }
    paged = result["breaches"]["paged"]
    doc["breaches"] = f"{result['breaches']['total']} in window ({len(paged)} paged)"
    doc["paged_breaches"] = [{"at": b["at"], "agent": b["agent"], "name": ctx.clip(b["name"], LIST_TEXT)} for b in paged]
    doc["top_delivery_required"] = [_row(g, ctx) for g in result["top"]]
    hints = []
    if result["delivery_required"] > len(result["top"]):
        hints.append(f"{ctx.run('groups')} for all {window_groups} groups in digest order")
    hints.append(f"{ctx.run('group <id>')} for one group, with the model's advisory verdict")
    if result["breaches"]["total"]:
        hints.append(f"{ctx.run('breaches')} for every breach and its signals")
    if result["health"]["status"] != "ok":
        hints.append(f"{ctx.run('health')} for every check")
    else:
        hints.append(f"{ctx.run('history')} for earlier windows")
    if ctx.truncated:
        hints.append(ctx.full_hint())
    return doc, hints


def groups_view(ctx: Context, args: argparse.Namespace, extra: list[str], result: dict[str, Any]) -> View:
    """``args`` needs ``category``, ``filter`` and ``fields`` (the raw comma list or None)."""
    rows = result["groups"]
    scope = []
    if args.category:
        scope.append(f"category {args.category}")
    if args.filter:
        scope.append(f"filter {_clean(args.filter)!r}")
    listed = result["listed_groups"]
    in_window = result["window_groups"]
    count = f"{len(rows)} of {result['matched']} matching"
    if scope:
        count += " " + " and ".join(scope)
    count += f" ({listed} listed" + (f" of {in_window} in window)" if listed != in_window else " in window)")
    doc: dict[str, Any] = {"count": count, "groups": [_row(g, ctx, extra) for g in rows]}
    hints = []
    if result["matched"] > len(rows):
        hints.append(f"{ctx.run(_groups_cmd(args, limit=result['matched']))} for all {result['matched']}")
    if rows:
        hints.append(f"{ctx.run('group <id>')} for one group, with the model's advisory verdict")
        if not extra:
            hints.append(ctx.fields_hint())
    elif scope:
        hints.append(f"{ctx.run('groups')} to list every group")
    if ctx.truncated:
        hints.append(ctx.full_hint())
    return doc, hints


def group_missing(ctx: Context, group_id: str) -> Failure:
    wanted = _clean(group_id)
    return Failure(f"no group with id {wanted}",
                   [f"{ctx.run('groups --filter ' + shlex.quote(wanted))} to search for it",
                    f"{ctx.run('groups')} to list ids"])


def group_view(ctx: Context, group: dict[str, Any]) -> View:
    agents = group["agents"] if ctx.full else group["agents"][:AGENTS_SHOWN]
    detail: dict[str, Any] = {
        "id": group["id"], "rule_id": group["rule_id"], "rule": ctx.clip(_rule(group), DETAIL_TEXT),
        "category": group["category"], "level": group["level"], "count": group["count"],
        "agents": [ctx.clip(a, LIST_TEXT) for a in agents],
    }
    if len(agents) < len(group["agents"]):
        ctx.truncated = True
        detail["agents_not_shown"] = len(group["agents"]) - len(agents)
    detail.update({"first_seen": group["first_seen"], "last_seen": group["last_seen"],
                   "protected": group["protected"], "tuning": group["tuning"],
                   "breach_signals": group["breach_signals"]})
    model = group["model"]
    if model is None:
        advisory: dict[str, Any] = {"ran": False, "note": "no model result for this group; policy decided alone"}
    else:
        advisory = {"ran": True, "note": ADVISORY, "name": model["name"], "verdict": model["verdict"],
                    "confidence": model["confidence"], "tags": model["tags"],
                    "summary": ctx.clip(model["summary"], DETAIL_TEXT)}
    doc = {"group": detail, "decision": group["decision"], "model_advisory": advisory}
    hints = [f"{ctx.run('group ' + shlex.quote(group['id']) + ' --full')} for the untruncated text"] if ctx.truncated else []
    return doc, hints


def breaches_view(ctx: Context, result: dict[str, Any]) -> View:
    rows = [{"at": b["at"], "agent": b["agent"], "name": ctx.clip(b["name"], LIST_TEXT), "paged": b["paged"],
             "signals": ctx.clip(" ".join(b["signals"]), LIST_TEXT)} for b in result["breaches"]]
    count = f"{result['total']} in window ({result['paged']} paged)" if rows else "0 breaches detected in this window"
    hints = [f"{ctx.run('groups --filter <agent>')} for the alert groups on one agent"] if rows else []
    if ctx.truncated:
        hints.append(ctx.full_hint())
    return {"count": count, "breaches": rows}, hints


def health_view(ctx: Context, result: dict[str, Any]) -> View:
    rows = [{"name": c["name"], "status": c["status"], "detail": ctx.clip(c["detail"], CHECK_TEXT)}
            for c in result["checks"]]
    doc = {"status": result["status"],
           "count": f"{result['not_ok']} of {len(rows)} checks not ok" if rows else "0 checks recorded",
           "checks": rows}
    hints = []
    if any(c["status"] != "ok" for c in result["checks"]):
        hints.append(f"{ctx.run('groups --category failed')} for groups the model or a boundary failed on")
    if ctx.truncated:
        hints.append(ctx.full_hint())
    return doc, hints


def history_view(ctx: Context, result: dict[str, Any]) -> View:
    rows = [{k: w[k] for k in ("start", "events", "groups", "delivered", "health_failure")} for w in result["history"]]
    count = (f"{result['windows']} earlier windows; {result['delivered']} delivered; "
             f"{result['health_failures']} with a health failure") if rows else "0 earlier windows recorded"
    return {"count": count, "history": rows}, []


# --- commands ---------------------------------------------------------------------------


def _load(ctx: Context) -> dict[str, Any]:
    from soc_thief import query
    try:
        return query.load(ctx.snapshot_path)
    except query.SnapshotError as error:
        raise Failure(str(error), ctx.load_hints()) from None


def cmd_overview(ctx: Context, args: argparse.Namespace, *, header: bool) -> None:
    from soc_thief import query
    result = query.overview(_load(ctx), top=TOP_GROUPS)
    if ctx.json:
        _emit_json(result)
        return
    _emit(*overview_view(ctx, result, header=header))


def parse_fields(fields: str | None) -> list[str]:
    """The ``--fields`` list, deduplicated in order. Raises Usage naming an unknown field."""
    if not fields:
        return []
    extra = [f.strip() for f in fields.split(",") if f.strip()]
    unknown = [f for f in extra if f not in GROUP_FIELDS]
    if unknown:
        raise Usage(f"unknown field {unknown[0]}; valid fields: {', '.join(GROUP_FIELDS)}", "groups")
    return list(dict.fromkeys(extra))


def cmd_groups(ctx: Context, args: argparse.Namespace) -> None:
    from soc_thief import query
    extra = parse_fields(args.fields)
    snap = _load(ctx)
    result = query.list_groups(snap, category=args.category, text=args.filter, limit=args.limit)
    if ctx.json:
        _emit_json(result)
        return
    _emit(*groups_view(ctx, args, extra, result))


def _groups_cmd(args: argparse.Namespace, *, limit: int) -> str:
    parts = ["groups"]
    if args.category:
        parts += ["--category", args.category]
    if args.filter:
        parts += ["--filter", shlex.quote(_clean(args.filter))]
    if args.fields:
        parts += ["--fields", shlex.quote(_clean(args.fields))]
    parts += ["--limit", str(limit)]
    return " ".join(parts)


def cmd_group(ctx: Context, args: argparse.Namespace) -> None:
    from soc_thief import query
    group = query.get_group(_load(ctx), args.id)
    if group is None:
        raise group_missing(ctx, args.id)
    if ctx.json:
        _emit_json(group)
        return
    _emit(*group_view(ctx, group))


def cmd_breaches(ctx: Context, args: argparse.Namespace) -> None:
    from soc_thief import query
    result = query.list_breaches(_load(ctx))
    if ctx.json:
        _emit_json(result)
        return
    _emit(*breaches_view(ctx, result))


def cmd_health(ctx: Context, args: argparse.Namespace) -> None:
    from soc_thief import query
    result = query.get_health(_load(ctx))
    if ctx.json:
        _emit_json(result)
        return
    _emit(*health_view(ctx, result))


def cmd_history(ctx: Context, args: argparse.Namespace) -> None:
    from soc_thief import query
    result = query.list_history(_load(ctx))
    if ctx.json:
        _emit_json(result)
        return
    _emit(*history_view(ctx, result))


def _generate(ctx: Context, module_name: str, argv: list[str], what: str) -> None:
    """Run the demo or state snapshot writer, keeping its prose off stdout."""
    if importlib.util.find_spec(f"soc_thief.{module_name}") is None:
        raise Failure(f"this install has no {what} writer", [])
    module = importlib.import_module(f"soc_thief.{module_name}")
    try:
        with contextlib.redirect_stdout(sys.stderr):
            code = module.main(argv)
    except SystemExit as stop:
        code = stop.code if isinstance(stop.code, int) else 1
    except Exception:
        code = 1
    if code != 0:
        raise Failure(f"{what} was not written (details on stderr)", [])


def cmd_demo(ctx: Context, args: argparse.Namespace) -> None:
    out = args.out or ctx.snapshot_path
    argv = ["--out", out]
    if args.seed is not None:
        argv += ["--seed", str(args.seed)]
    if args.now:
        argv += ["--now", args.now]
    _generate(ctx, "demo", argv, "demo snapshot")
    _written(ctx, out, "demo")


def cmd_snapshot(ctx: Context, args: argparse.Namespace) -> None:
    out = args.out or ctx.snapshot_path
    _generate(ctx, "snapshot", ["--state", args.state, "--out", out], "state snapshot")
    _written(ctx, out, "state")


def _written(ctx: Context, out: str, source: str) -> None:
    target = shlex.quote(_clean(out))
    reader = ctx.prefix if out == ctx.snapshot_path else f"soc-thief --snapshot {target}"
    _emit({"wrote": _clean(out), "source": source},
          [f"Run `{reader}` for the overview", f"Run `{reader} groups` to list groups"])


HANDLERS: dict[str, Callable[[Context, argparse.Namespace], None]] = {
    "status": lambda ctx, args: cmd_overview(ctx, args, header=False),
    "groups": cmd_groups,
    "group": cmd_group,
    "breaches": cmd_breaches,
    "health": cmd_health,
    "history": cmd_history,
    "demo": cmd_demo,
    "snapshot": cmd_snapshot,
}


# --- help and errors --------------------------------------------------------------------


def command_help(command: str | None) -> str:
    from soc_thief import toon
    if command is None:
        doc = {"usage": "soc-thief [COMMAND] [--snapshot PATH] [--json] [--full]",
               "description": DESCRIPTION + ". With no command it prints the overview.",
               "commands": [{"name": name, "does": spec[1].split(". ")[0].rstrip(".")} for name, spec in COMMANDS.items()],
               "flags": [{"flag": f, "default": d, "meaning": m} for f, d, m in _GLOBAL_HELP],
               "exit_codes": "0 ok, 1 failed, 2 usage error"}
        examples = ["soc-thief", "soc-thief groups --category new", "soc-thief group <id>"]
    else:
        usage, description, flags, examples = COMMANDS[command]
        doc = {"usage": usage, "description": description,
               "flags": [{"flag": f, "default": d, "meaning": m} for f, d, m in flags + _GLOBAL_HELP]}
    return toon.encode(doc) + "\n" + toon.help_block(examples, name="examples")


def _print_error(message: str, hints: list[str], as_json: bool) -> None:
    if as_json:
        _emit_json({"error": message, "help": hints})
        return
    _emit({"error": message}, hints)


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0] in VERSION_FLAGS:
        print(version())
        return EXIT_OK
    environ = dict(os.environ if environ is None else environ)
    as_json = "--json" in argv
    try:
        args = parse(argv)
    except Usage as error:
        _print_usage(str(error), error.command, as_json)
        return EXIT_USAGE
    command = getattr(args, "command", None)
    if getattr(args, "help", False):
        print(command_help(command))
        return EXIT_OK
    ctx = Context(args, environ)
    try:
        if command is None:
            cmd_overview(ctx, args, header=True)
        else:
            HANDLERS[command](ctx, args)
    except Usage as error:
        _print_usage(str(error), error.command, ctx.json)
        return EXIT_USAGE
    except Failure as error:
        _print_error(_clean(str(error)), error.hints, ctx.json)
        return EXIT_FAILED
    return EXIT_OK


def _print_usage(message: str, command: str | None, as_json: bool) -> None:
    """A usage error carries the command's own help, so the agent corrects it in one turn."""
    message = _clean(message)
    if as_json:
        _emit_json({"error": message, "valid_flags": _flags_for(command)})
        return
    from soc_thief import toon
    print(toon.encode({"error": message}) + "\n" + command_help(command))


if __name__ == "__main__":
    raise SystemExit(main())
