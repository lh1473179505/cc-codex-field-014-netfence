"""Peer-address admission engine. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from netfence.parse import ParsedAddr
from netfence.policy import Policy


def admit_addr(parsed: ParsedAddr, policy: Policy) -> dict[str, Any]:
    raise NotImplementedError("admit_addr is not implemented in this snapshot")
