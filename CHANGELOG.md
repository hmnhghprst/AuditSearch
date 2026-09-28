# Changelog

All notable changes to AuditSearch are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] — `ausearch`-style `-k <keyword>` flag

### Added
- Bare `-k <keyword>` flag, mirroring `ausearch -k <keyword>`: filters
  events by the auditd watch key set via `auditctl ... -k <keyword>`.
  Unlike `-i`/`-correlate` (single-token boolean flags), `-k`'s value is
  a *separate* SPL token with no `=` in either part, so
  `_protocol_v2_option_parser()` now carries a small piece of state
  across sequential calls to merge the two tokens into `key=<value>`.
  `-k`, `-k=<keyword>`, `--key`, `--key=<keyword>`, and the existing
  `key=<keyword>` are all equivalent and can be freely mixed with `-i`
  in any order (`auditsearch -i -k rootcmd` and
  `auditsearch -k rootcmd -i` behave identically). A bare `-k` with no
  following value now reports a clear error via the Job Inspector
  instead of silently doing nothing or crashing.