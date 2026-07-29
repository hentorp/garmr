import importlib.util
import io
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("garmr-pgaudit-ship.py")
SPEC = importlib.util.spec_from_file_location("garmr_pgaudit_ship", SCRIPT)
SHIPPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHIPPER)


class CsvRecordTests(unittest.TestCase):
    def test_timestamp_line_inside_quoted_field_does_not_split_record(self):
        row = (
            '2026-07-26 12:00:00,user,"AUDIT: SELECT \'first line\n'
            "2026-01-01 00:00:00 attacker-controlled tail'" + '"\n'
        )

        self.assertEqual(list(SHIPPER.records_from(io.StringIO(row))), [row.rstrip("\n")])

    def test_incremental_parser_waits_for_complete_multiline_record(self):
        parser = SHIPPER.CsvRecordBuffer()

        self.assertEqual(parser.feed('2026-07-26 12:00:00,user,"AUDIT:\n'), [])
        self.assertEqual(
            parser.feed('SELECT 1"\n2026-07-26 12:00:01,user,"AUDIT: SELECT 2"\n'),
            [
                '2026-07-26 12:00:00,user,"AUDIT:\nSELECT 1"',
                '2026-07-26 12:00:01,user,"AUDIT: SELECT 2"',
            ],
        )


if __name__ == "__main__":
    unittest.main()
