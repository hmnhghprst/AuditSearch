import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from audit_lexicon.parser import parse_audit_line


SYSCALL_LINE = (
    'type=SYSCALL msg=audit(1699999999.123:456): arch=c000003e syscall=59 '
    'success=yes exit=0 a0=55a1 a1=0 a2=0 a3=0 items=2 ppid=1234 pid=5678 '
    'auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 '
    'tty=pts0 ses=3 comm="bash" exe="/bin/bash" '
    'key="6175646974636865636b"'
)

PROCTITLE_LINE = (
    'type=PROCTITLE msg=audit(1699999999.123:456): '
    'proctitle=2F62696E2F6C7300612D6C61'
)


class TestParseAuditLine(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(parse_audit_line(""), {})
        self.assertEqual(parse_audit_line(None), {})

    def test_type_field(self):
        fields = parse_audit_line(SYSCALL_LINE)
        self.assertEqual(fields["type"], "SYSCALL")

    def test_msg_becomes_epoch_and_serial(self):
        fields = parse_audit_line(SYSCALL_LINE)
        self.assertEqual(fields["audit_epoch"], "1699999999.123")
        self.assertEqual(fields["audit_serial"], "456")
        self.assertNotIn("msg", fields)

    def test_quoted_values_are_unquoted(self):
        fields = parse_audit_line(SYSCALL_LINE)
        self.assertEqual(fields["comm"], "bash")
        self.assertEqual(fields["exe"], "/bin/bash")

    def test_numeric_fields_kept_as_strings(self):
        fields = parse_audit_line(SYSCALL_LINE)
        self.assertEqual(fields["syscall"], "59")
        self.assertEqual(fields["uid"], "0")
        self.assertEqual(fields["auid"], "1000")

    def test_hex_blob_field_not_touched_by_parser(self):
        # Decoding is the decoder's job, not the parser's.
        fields = parse_audit_line(PROCTITLE_LINE)
        self.assertEqual(fields["proctitle"], "2F62696E2F6C7300612D6C61")


if __name__ == "__main__":
    unittest.main()
