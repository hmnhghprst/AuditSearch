"""
Tokenize one raw auditd record line into a flat dict of fields.

Design notes
------------
We deliberately re-parse `_raw` ourselves rather than relying on Splunk's
automatic key=value field extraction (KV_MODE=auto):

* It keeps this command correct regardless of how KV_MODE, SEDCMD, or other
  per-sourcetype settings are configured in the environment it's dropped
  into — there is no ingestion-time or props.conf dependency at all.
* auditd's own quirks (the `msg=audit(<epoch>.<ms>:<serial>):` token, hex
  blobs with no delimiters, embedded `=` inside SELinux `subj=` values)
  are handled explicitly here instead of relying on generic KV heuristics.

A single auditd record line looks like:

    type=SYSCALL msg=audit(1699999999.123:456): arch=c000003e syscall=59 \
    success=yes exit=0 ... comm="bash" exe="/bin/bash" key="watched"

Every field is `key=value`, where `value` is either a double-quoted string
or a single whitespace-free token (which may itself be a hex blob).
"""

import re

_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_MSG_RE = re.compile(r"audit\((\d+)\.(\d+):(\d+)\):?")


def parse_audit_line(raw):
    if not raw:
        return {}

    fields = {}
    for match in _KV_RE.finditer(raw):
        key, value = match.group(1), match.group(2)

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]

        if key == "msg":
            msg_match = _MSG_RE.search(value)
            if msg_match:
                epoch_sec, epoch_ms, serial = msg_match.groups()
                fields["audit_epoch"] = "{}.{}".format(epoch_sec, epoch_ms)
                fields["audit_serial"] = serial
                continue 
            fields[key] = value
            continue

        fields[key] = value

    return fields
