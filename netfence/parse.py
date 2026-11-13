"""Classify a raw peer-address string.

This module does not decide allow or deny. It records the notation kind
(canonical dotted IPv4, dword, octal/leading-zero, short form, hex,
IPv6, IPv4-mapped IPv6, or unknown) plus flags such as zone ids and
port suffixes, so inspect can print them and admit can apply policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ParsedAddr:
    raw: str
    kind: str = "unknown"
    dotted_parts: list[str] | None = None
    has_leading_zero: bool = False
    has_zone: bool = False
    zone_id: str | None = None
    has_brackets: bool = False
    has_port: bool = False
    port: int | None = None
    port_text: str | None = None
    ipv6_text: str | None = None
    ipv4_tail: str | None = None
    has_nul: bool = False
    has_whitespace: bool = False
    has_controls: bool = False
    parse_ok: bool = False
    parse_error: str | None = None
    flags: list[str] = field(default_factory=list)


_HEX_IPv4 = re.compile(r"^0x[0-9A-Fa-f]+(?:\.0x[0-9A-Fa-f]+){0,3}$")
_DWORD = re.compile(r"^[0-9]{1,10}$")
_DOTTED = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
_IPV4_DOTTED_STRICT = re.compile(r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")


def _scan(raw: str) -> dict[str, bool]:
    return {
        "has_nul": "\x00" in raw,
        "has_whitespace": any(ch in raw for ch in " \t\r\n"),
        "has_controls": any(ord(ch) < 32 or ord(ch) == 127 for ch in raw),
    }


def _flag_names(parsed: ParsedAddr) -> list[str]:
    names = []
    for name in ("has_nul", "has_whitespace", "has_controls", "has_leading_zero", "has_zone", "has_brackets", "has_port"):
        if getattr(parsed, name):
            names.append(name[4:] if name.startswith("has_") else name)
    return names


def _strip_brackets_and_port(raw: str) -> tuple[str, bool, bool, str | None, int | None, str | None]:
    """Return core, has_brackets, has_port, port_text, port, error."""
    has_brackets = False
    has_port = False
    port_text = None
    port = None
    core = raw
    if raw.startswith("["):
        close = raw.find("]")
        if close < 0:
            return raw, True, False, None, None, "unclosed brackets"
        has_brackets = True
        core = raw[1:close]
        after = raw[close + 1 :]
        if after == "":
            pass
        elif after.startswith(":"):
            has_port = True
            port_text = after[1:]
        else:
            return core, True, False, None, None, "junk after brackets"
    elif raw.count(":") == 1 and re.match(r"^[^:]+:\d+$", raw):
        # dotted IPv4 or token with a trailing port, not IPv6
        host, port_text = raw.rsplit(":", 1)
        if "." in host or _DWORD.match(host) or host.lower().startswith("0x"):
            has_port = True
            core = host
    if port_text is not None:
        if port_text == "" or not port_text.isdigit():
            return core, has_brackets, True, port_text, None, "invalid port"
        port = int(port_text)
        if port > 65535:
            return core, has_brackets, True, port_text, None, "invalid port"
    return core, has_brackets, has_port, port_text, port, None


def _classify_ipv4_token(token: str) -> tuple[str, list[str] | None, bool, str | None]:
    """Return kind, dotted_parts, has_leading_zero, error."""
    if _HEX_IPv4.match(token):
        return "ipv4_hex", token.split("."), False, None
    if _DWORD.match(token):
        # A single decimal number used as an IPv4 dword, including 2130706433.
        # "0".."255" as a lone number is still a dword / short form, not dotted.
        return "ipv4_dword", None, len(token) > 1 and token.startswith("0"), None
    if _DOTTED.match(token):
        parts = token.split(".")
        leading = any(len(p) > 1 and p.startswith("0") for p in parts)
        if leading:
            # 10.01.2.3 or 0177.0.0.1 — octal-style / leading-zero form
            return "ipv4_octal", parts, True, None
        if len(parts) != 4:
            return "ipv4_short", parts, False, None
        if _IPV4_DOTTED_STRICT.match(token):
            return "ipv4_dotted", parts, False, None
        return "ipv4_dotted", parts, False, "octet out of range"
    return "unknown", None, False, None


def _looks_like_ipv6(token: str) -> bool:
    if token.count(":") < 2:
        return False
    # letters only a-f, colon, optionally an embedded dotted tail, optional zone
    body = token
    if "%" in body:
        body = body.split("%", 1)[0]
    if "." in body:
        head, tail = body.rsplit(":", 1) if ":" in body else ("", body)
        # ::ffff:10.2.3.4 style
        return True
    return all(ch in "0123456789abcdefABCDEF:" for ch in body) and "::" in body or (body.count(":") >= 2 and all(ch in "0123456789abcdefABCDEF:" for ch in body))


def parse_addr(raw: str) -> ParsedAddr:
    if not isinstance(raw, str):
        return ParsedAddr(raw="", parse_ok=False, parse_error="addr must be a string")
    parsed = ParsedAddr(raw=raw, **_scan(raw))
    if parsed.has_nul or parsed.has_whitespace or parsed.has_controls:
        parsed.parse_error = "control or whitespace in address"
        parsed.flags = _flag_names(parsed)
        return parsed

    core, has_brackets, has_port, port_text, port, err = _strip_brackets_and_port(raw)
    parsed.has_brackets = has_brackets
    parsed.has_port = has_port
    parsed.port_text = port_text
    parsed.port = port
    if err:
        parsed.parse_error = err
        parsed.flags = _flag_names(parsed)
        return parsed

    zone_id = None
    if "%" in core:
        core, zone_id = core.split("%", 1)
        parsed.has_zone = True
        parsed.zone_id = zone_id

    if _looks_like_ipv6(core):
        parsed.ipv6_text = core
        # IPv4-mapped: :ffff:x.x.x.x or :ffff:hhhh:hhhh at the end
        lower = core.lower()
        mapped = re.search(r"(?:^|:)ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", lower)
        mapped_hex = re.search(r"(?:^|:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$", lower)
        if mapped:
            parsed.kind = "ipv4_mapped"
            parsed.ipv4_tail = mapped.group(1)
        elif mapped_hex:
            a = int(mapped_hex.group(1), 16)
            b = int(mapped_hex.group(2), 16)
            parsed.kind = "ipv4_mapped"
            parsed.ipv4_tail = f"{a >> 8}.{a & 0xFF}.{b >> 8}.{b & 0xFF}"
        else:
            parsed.kind = "ipv6"
        parsed.parse_ok = True
        parsed.flags = _flag_names(parsed)
        return parsed

    kind, parts, leading, verr = _classify_ipv4_token(core)
    parsed.kind = kind
    parsed.dotted_parts = parts
    parsed.has_leading_zero = leading
    if verr:
        parsed.parse_error = verr
        parsed.flags = _flag_names(parsed)
        return parsed
    if kind == "unknown":
        parsed.parse_error = "unrecognized address"
        parsed.flags = _flag_names(parsed)
        return parsed
    parsed.parse_ok = True
    parsed.flags = _flag_names(parsed)
    return parsed


def parsed_to_dict(parsed: ParsedAddr) -> dict:
    return {
        "raw": parsed.raw,
        "kind": parsed.kind,
        "dotted_parts": parsed.dotted_parts,
        "ipv6_text": parsed.ipv6_text,
        "ipv4_tail": parsed.ipv4_tail,
        "zone_id": parsed.zone_id,
        "port": parsed.port,
        "port_text": parsed.port_text,
        "parse_ok": parsed.parse_ok,
        "parse_error": parsed.parse_error,
        "flags": parsed.flags,
    }
