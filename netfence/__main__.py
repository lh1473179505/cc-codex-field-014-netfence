"""CLI. inspect already works; admit is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netfence.parse import parse_addr, parsed_to_dict
from netfence.policy import PolicyError, load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netfence")
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="print the classified notation of a peer address")
    ins.add_argument("--addr", required=True, help="address string, a path, or @path")

    adm = sub.add_parser("admit", help="fail-closed admission check for a peer address")
    adm.add_argument("--addr", required=True, help="address string, a path, or @path")
    adm.add_argument("--policy", required=True)
    adm.add_argument("--report", required=True)
    return p


def _read_addr(value: str) -> str:
    if value.startswith("@"):
        text = Path(value[1:]).read_text(encoding="utf-8")
        if text.endswith("\r\n"):
            return text[:-2]
        if text.endswith("\n"):
            return text[:-1]
        return text
    try:
        path = Path(value)
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if text.endswith("\r\n"):
                return text[:-2]
            if text.endswith("\n"):
                return text[:-1]
            return text
    except OSError:
        pass
    return value


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw = _read_addr(args.addr)
    except OSError as exc:
        print(f"failed to read addr: {exc}", file=sys.stderr)
        return 2

    parsed = parse_addr(raw)

    if args.cmd == "inspect":
        print(json.dumps(parsed_to_dict(parsed), ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "admit":
        try:
            policy = load_policy(args.policy)
        except (PolicyError, OSError) as exc:
            print(f"failed to load policy: {exc}", file=sys.stderr)
            return 2
        from netfence.engine import admit_addr

        try:
            report = admit_addr(parsed, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"admit failed unexpectedly: {exc}", file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
