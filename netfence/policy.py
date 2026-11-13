"""Peer-address admission policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    allow_cidrs: list[str]
    deny_cidrs: list[str]
    allow_loopback: bool
    allow_link_local: bool
    allow_multicast: bool
    allow_unspecified: bool
    allow_documentation: bool
    allow_broadcast: bool
    allow_zone_id: bool
    allow_port_suffix: bool
    raw: dict[str, Any] = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"failed to read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")

    def _strlist(name: str, default: list[str] | None = None) -> list[str]:
        val = data.get(name, default if default is not None else [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise PolicyError(f"{name} must be an array of strings")
        return list(val)

    allow_cidrs = _strlist("allow_cidrs")
    if not allow_cidrs:
        raise PolicyError("allow_cidrs must contain at least one CIDR")

    return Policy(
        allow_cidrs=allow_cidrs,
        deny_cidrs=_strlist("deny_cidrs"),
        allow_loopback=bool(data.get("allow_loopback", False)),
        allow_link_local=bool(data.get("allow_link_local", False)),
        allow_multicast=bool(data.get("allow_multicast", False)),
        allow_unspecified=bool(data.get("allow_unspecified", False)),
        allow_documentation=bool(data.get("allow_documentation", False)),
        allow_broadcast=bool(data.get("allow_broadcast", False)),
        allow_zone_id=bool(data.get("allow_zone_id", False)),
        allow_port_suffix=bool(data.get("allow_port_suffix", False)),
        raw=data,
    )
