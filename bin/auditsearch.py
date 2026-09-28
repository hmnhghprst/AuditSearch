#!/usr/bin/env python
"""
AuditSearch — a search-time-only Splunk command that interprets raw Linux
auditd events (arch codes, syscall numbers, hex-encoded fields, errno exit
codes) without any ingestion-time parsing, scripted input, or dependency on
binaries installed on the source host.

    index=linux_audit sourcetype=auditd
    | auditsearch -i
    | auditsearch -i type=EXECVE
    | auditsearch -i auid=1000
    | auditsearch -i -k rootcmd
    | auditsearch -i key=sshd_config

This module is intentionally thin: it owns only search-command plumbing
(argument parsing, iterating records, field assignment). All auditd
decoding logic lives in the standalone, dependency-free `audit_lexicon`
package next to this file, so it can be unit tested without a Splunk
instance and reused by future modes (e.g. multi-record correlation).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

from audit_lexicon.parser import parse_audit_line
from audit_lexicon.decoder import interpret_record


@Configuration(distributed=True)
class AuditSearchCommand(StreamingCommand):
    """Interpret raw Linux auditd events at search time.

    ##Syntax

    auditsearch [-i] [type=<audit-record-type>] [auid=<uid>] [-k <keyword>|key=<audit-key>]

    ##Description

    Parses auditd `key=value` records directly out of `_raw` (independent
    of any KV_MODE / field-extraction configuration) and, with `-i`,
    interprets numeric/hex-encoded values into human-readable form the
    same way `ausearch -i` does: `arch=c000003e` becomes `x86_64`,
    `syscall=59` becomes `execve`, and hex-encoded fields such as
    `PROCTITLE` are decoded to their original text. The original indexed
    event (`_raw`) is never modified; each interpreted field's original
    raw value is preserved alongside it as `<field>_raw`.

    ##Example

    Interpret every event and show only EXECVE records for a given user::

        index=linux_audit sourcetype=auditd
        | auditsearch -i type=EXECVE auid=1000
    """

    i = Option(
        doc="""
        **Syntax:** i=<bool>
        **Description:** Interpret decoded/numeric auditd fields into
        human-readable form, equivalent to `ausearch -i`. Without this
        flag, auditsearch only extracts the raw fields from `_raw` as
        distinct, searchable fields (arch, syscall, uid, exit, ... as
        auditd wrote them) and does not translate any values.
        """,
        require=False,
        validate=validators.Boolean(),
        default=False,
    )

    type = Option(
        doc="""
        **Syntax:** type=<string>
        **Description:** Only pass through events whose auditd `type`
        field equals this value (e.g. `type=EXECVE`). Comparison is
        case-insensitive.
        """,
        require=False,
    )

    auid = Option(
        doc="""
        **Syntax:** auid=<string>
        **Description:** Only pass through events whose `auid` field
        equals this value.
        """,
        require=False,
    )

    key = Option(
        doc="""
        **Syntax:** key=<string>
        **Description:** Only pass through events whose auditd `key`
        field equals this value -- the same watch tag set via `-k` in an
        `auditctl` rule (e.g. `auditctl -w /etc/passwd -p wa -k
        rootcmd`). Compares against the *decoded* key when `-i` is also
        given (auditd hex-encodes keys containing spaces). The
        `ausearch`-compatible bare forms `-k <keyword>` and
        `-k=<keyword>` are also accepted and are equivalent to
        `key=<keyword>`; see `_protocol_v2_option_parser` below for how.
        """,
        require=False,
    )

    correlate = Option(
        doc="""
        **Syntax:** correlate=<bool>
        **Description:** Reserved for a future release. Will correlate
        SYSCALL/EXECVE/CWD/PATH/PROCTITLE/... records that share the same
        `audit(timestamp:serial)` transaction ID into one logical event.
        Not implemented in this version; set to true has no effect beyond
        adding an `audit_correlate_pending=1` marker field so downstream
        searches can detect the gap explicitly rather than silently.
        """,
        require=False,
        validate=validators.Boolean(),
        default=False,
    )

    _BOOLEAN_FLAG_ALIASES = {
        "-i": ("i", "t"),
        "-correlate": ("correlate", "t"),
        "--correlate": ("correlate", "t"),
    }

    # Maps a bare CLI flag to the Option name it supplies a value for.
    _VALUE_FLAG_ALIASES = {
        "-k": "key",
        "--key": "key",
    }

    def __init__(self):
        super().__init__()
        self._pending_value_option = None

    def _protocol_v2_option_parser(self, arg):
        if self._pending_value_option is not None:
            option_name = self._pending_value_option
            self._pending_value_option = None
            return [option_name, arg]

        boolean_alias = self._BOOLEAN_FLAG_ALIASES.get(arg)
        if boolean_alias is not None:
            return list(boolean_alias)

        value_option = self._VALUE_FLAG_ALIASES.get(arg)
        if value_option is not None:
            self._pending_value_option = value_option

            return ["_auditsearch_pending_flag_value"]

        for prefix, option_name in (("-k=", "key"), ("--key=", "key")):
            if arg.startswith(prefix):
                return [option_name, arg[len(prefix):]]

        return super()._protocol_v2_option_parser(arg)

    def stream(self, records):
        if self._pending_value_option is not None:
            # "-k" (or "--key") was given with no following value token.
            flag = "-k" if self._pending_value_option == "key" else self._pending_value_option
            self.write_error(f"Missing value after {flag}; expected e.g. `{flag} rootcmd`.")
            self._pending_value_option = None

        interpret = bool(self.i)
        type_filter = self.type.lower() if self.type else None
        auid_filter = self.auid
        key_filter = self.key
        correlate_requested = bool(self.correlate)

        for record in records:
            raw = record.get("_raw")
            if not raw:
                yield record
                continue

            try:
                fields = parse_audit_line(raw)
            except Exception as exc:  
                self.add_field(record, "auditsearch_error", str(exc))
                yield record
                continue

            if not fields:
                yield record
                continue

            if type_filter and fields.get("type", "").lower() != type_filter:
                continue
            if auid_filter and fields.get("auid") != auid_filter:
                continue

            if interpret:
                interpret_record(fields)

            if key_filter and fields.get("key") != key_filter:
                continue

            for field_name, value in fields.items():
                self.add_field(record, field_name, value)

            if correlate_requested:
                self.add_field(record, "audit_correlate_pending", "1")

            yield record


dispatch(AuditSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
