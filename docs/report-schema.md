# Report schema

`admit` always writes a JSON object to `--report` when it can produce a decision of `allow` or `deny`.

```json
{
  "decision": "allow",
  "reason_codes": [],
  "canonical": "10.2.3.4",
  "kind": "ipv4_dotted",
  "family": "ipv4"
}
```

- `decision` is `allow` or `deny`.
- `reason_codes` is an array of strings. It is empty on `allow`. On `deny` it contains one or more codes from `docs/admit-rules.md` (`malformed`, `unexpected_port`, `zone_id`, `noncanonical_ipv4`, `loopback`, `link_local`, `multicast`, `unspecified`, `documentation`, `broadcast`, `denied_cidr`, `not_allowed`). If several checks fail, include all that were evaluated; checks may stop after the first definite deny, in which case only the codes reached so far appear.
- `canonical` is the canonical address string described in the rules, or `null` when no address could be parsed.
- `kind` is the parser's kind string (or `unknown`).
- `family` is `ipv4` or `ipv6` after mapping, or `null` when unparseable. A mapped address has `family` `ipv4`.
