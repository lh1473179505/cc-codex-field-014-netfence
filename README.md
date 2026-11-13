# netfence

A small fail-closed admission check for peer address literals. Classification of the raw string already works. `inspect` can print the notation kind (canonical dotted IPv4, dword, octal, short form, mapped IPv6, and so on). `admit` is still a stub in this snapshot.

This tool is meant to sit at an access layer that used to hand the peer string to a loose parser. Dword forms such as `2130706433`, leading-zero octets, and IPv4-mapped IPv6 can otherwise sneak past a CIDR allowlist or hide loopback.

## Requirements

- Python 3.11+
- Standard library only (`ipaddress` is fine on already-canonical literals)
- No containers, no DNS, no `socket.inet_aton`

## Already working

```bash
python -m netfence inspect --addr fixtures/addrs/v4-canonical.txt
```

`--addr` may be an address string, a path, or `@path`. When the value is a file, a single trailing newline is stripped.

The policy shape is in `fixtures/policy.json`. Admission rules are in `docs/admit-rules.md`. The report object is in `docs/report-schema.md`.

## Intended CLI

```bash
python -m netfence admit \
  --addr fixtures/addrs/v4-canonical.txt \
  --policy fixtures/policy.json \
  --report /tmp/netfence-report.json
```

Parameter names are fixed in `netfence/__main__.py`. Keep them.

## Layout

- `netfence/parse.py` — notation classification and anomaly flags
- `netfence/policy.py` — policy loader
- `netfence/engine.py` — `admit_addr` (not implemented yet)
- `fixtures/addrs/` — allowed and rejected peer literals
