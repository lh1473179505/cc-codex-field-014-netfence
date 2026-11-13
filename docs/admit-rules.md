# Admit rules

`admit` is fail-closed. A peer address is only allowed when every check below succeeds. If a check does not unambiguously succeed, the decision is `deny`. An unreadable policy or an unreadable `--addr` file is a process error (exit 2), not a deny report. A candidate that can be read as a string, even when it is not a recognized address, must produce a deny report and exit 1.

Reuse `parse_addr` and `load_policy`. Do not call `socket.inet_aton` or any other legacy parser that accepts octal, hex, dword, or short forms. The standard library `ipaddress` module may be used on a string that has already been accepted as a canonical dotted IPv4 or a well-formed IPv6 literal.

## Notation

- If the raw string contains NUL, whitespace, or any other C0 / DEL character, deny with `malformed`.
- If `parse_ok` is false, or `kind` is `unknown`, deny with `malformed`.
- A port suffix is `unexpected_port` unless `allow_port_suffix` is true (the public policy leaves it false).
- A zone identifier (`fe80::1%eth0`) is `zone_id` unless `allow_zone_id` is true (the public policy leaves it false).
- Kinds `ipv4_dword`, `ipv4_hex`, `ipv4_octal`, and `ipv4_short` are `noncanonical_ipv4`. Leading zeros on a decimal octet (`10.01.2.3`, `0177.0.0.1`) are included in this set. Do not canonicalize them and retry.
- `ipv4_dotted` is accepted only when it has exactly four decimal octets in `0..255` with no leading zeros (the single octet `0` is allowed).
- IPv6 literals must be well-formed. If `ipaddress.IPv6Address` rejects the literal (after stripping a zone id that was already handled above), deny with `malformed`.

## IPv4-mapped IPv6

- A kind of `ipv4_mapped` (`::ffff:10.2.3.4` or `::ffff:0a02:0304`) is converted to the embedded IPv4 address, and every subsequent special-use and CIDR check uses that IPv4 address. The report's `canonical` field is the dotted IPv4 form.
- `::ffff:127.0.0.1` is therefore loopback, not a v6 address outside `127.0.0.0/8`.
- This conversion is mandatory. There is no policy switch that leaves a mapped address in IPv6 form for membership tests.

## Special-use ranges

These checks run after mapping, and they apply even when the address also sits inside `allow_cidrs`:

- IPv4 `127.0.0.0/8` and IPv6 `::1` are `loopback` unless `allow_loopback` is true.
- IPv4 `169.254.0.0/16` and IPv6 `fe80::/10` are `link_local` unless `allow_link_local` is true.
- Multicast (IPv4 `224.0.0.0/4`, IPv6 `ff00::/8`) is `multicast` unless `allow_multicast` is true.
- IPv4 `0.0.0.0/32` and IPv6 `::` are `unspecified` unless `allow_unspecified` is true. Other addresses in `0.0.0.0/8` are also `unspecified`.
- Documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32` are `documentation` unless `allow_documentation` is true.
- IPv4 `255.255.255.255` is `broadcast` unless `allow_broadcast` is true.

The public policy leaves all of these flags false.

## CIDR membership

- `deny_cidrs` is checked first and wins. A match is `denied_cidr`. The public policy denies `10.255.0.0/16`.
- After that, the address must fall in at least one entry of `allow_cidrs`. Otherwise `not_allowed`.
- The public policy allows `10.0.0.0/8`, `192.168.10.0/24`, and `fd12:3456:789a::/48`.
- IPv4 addresses are only tested against IPv4 CIDRs; IPv6 addresses (that were not mapped) are only tested against IPv6 CIDRs.

## Canonical form

On `allow` and on a deny that still produced a usable address, `canonical` is:

- dotted IPv4 (`10.2.3.4`) for IPv4 and for mapped IPv6
- compressed lowercase IPv6 (`fd12:3456:789a::1`) for non-mapped IPv6, without a zone id or brackets

On a deny where no address could be parsed, `canonical` is `null`.

## Public fixtures

Against `fixtures/policy.json`:

- `fixtures/addrs/v4-canonical.txt` (`10.2.3.4`) → allow, canonical `10.2.3.4`
- `fixtures/addrs/v4-lan.txt` (`192.168.10.20`) → allow
- `fixtures/addrs/v6-ula.txt` (`fd12:3456:789a::1`) → allow, canonical `fd12:3456:789a::1`
- `fixtures/addrs/v4-mapped-ok.txt` (`::ffff:10.2.3.4`) → allow, canonical `10.2.3.4`
- `fixtures/addrs/v4-loopback.txt` (`127.0.0.1`) → deny / `loopback`
- `fixtures/addrs/v4-mapped-loopback.txt` (`::ffff:127.0.0.1`) → deny / `loopback`
- `fixtures/addrs/v4-dword.txt` (`2130706433`) → deny / `noncanonical_ipv4`
- `fixtures/addrs/v4-octal.txt` (`0177.0.0.1`) → deny / `noncanonical_ipv4`
- `fixtures/addrs/v4-leading-zero.txt` (`10.01.2.3`) → deny / `noncanonical_ipv4`
- `fixtures/addrs/v4-short.txt` (`10.2`) → deny / `noncanonical_ipv4`
- `fixtures/addrs/v4-hole.txt` (`10.255.1.2`) → deny / `denied_cidr`
- `fixtures/addrs/v4-outside.txt` (`11.1.2.3`) → deny / `not_allowed`

## Exit status

- `allow` → exit 0
- `deny` → exit 1
- Policy load errors or an unreadable `--addr` file → exit 2, and do not write a report that claims `allow`.
