"""Write a private, unapplied host-egress proposal for the opt-in Jev trial."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import stat
from pathlib import Path
from urllib.parse import urlsplit

from soc_thief.model import _JEV_URL


class JevEgressError(RuntimeError):
    pass


_DROP = re.compile(
    r'^(?P<indent>[ \t]*)meta skuid (?P<uid>[0-9]+) counter log prefix "soc-thief-drop: " '
    r'level info drop comment "soc-thief: no external egress"$', re.M)


def propose(policy: str, addresses: object) -> str:
    """Insert one narrowly scoped HTTPS accept immediately before the existing drop."""
    if (type(policy) is not str or "Jev trial HTTPS" in policy
            or type(addresses) not in (tuple, list)
            or not all(type(value) is str for value in addresses)):
        raise JevEgressError("Jev egress proposal is invalid")
    try:
        ips = sorted({ipaddress.IPv4Address(value) for value in addresses})
        if not 1 <= len(ips) <= 8 or not all(ip.is_global for ip in ips):
            raise ValueError
        matches = list(_DROP.finditer(policy))
        if len(matches) != 1:
            raise ValueError
        match = matches[0]
        destinations = ", ".join(str(ip) for ip in ips)
        rule = (f'{match.group("indent")}ip daddr {{ {destinations} }} tcp dport 443 accept '
                f'comment "Jev trial HTTPS, review required"\n')
        return policy[:match.start()] + rule + policy[match.start():]
    except (TypeError, ValueError, ipaddress.AddressValueError):
        raise JevEgressError("Jev egress proposal is invalid") from None


def _read_policy(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
                raise ValueError
            raw = stream.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError
        return raw.decode("utf-8")
    except (OSError, ValueError, UnicodeError):
        raise JevEgressError("Jev egress source is invalid") from None


def write_proposal(source: Path, output: Path) -> None:
    try:
        origin = urlsplit(_JEV_URL)
        if origin.scheme != "https" or not origin.hostname:
            raise ValueError
        addresses = tuple({entry[4][0] for entry in socket.getaddrinfo(
            origin.hostname, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)})
        text = propose(_read_policy(source), addresses)
        parent = output.parent.stat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or parent.st_mode & 0o077):
            raise ValueError
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    except (OSError, ValueError, socket.gaierror):
        raise JevEgressError("Jev egress proposal failed") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(1, "Invalid Jev egress arguments; use --help.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--source", required=True, help="Current host policy file")
    parser.add_argument("--output", required=True, help="New private proposal path")
    args = parser.parse_args(argv)
    try:
        write_proposal(Path(args.source), Path(args.output))
    except JevEgressError:
        print("Jev egress proposal failed; host policy unchanged.")
        return 1
    print("Private Jev egress proposal written; host policy unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
