import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_csv


class EmptyBearerTraceTests(unittest.TestCase):
    def make_raw(self, root):
        root.mkdir(parents=True)
        (root / 'MmWaveSinrTime.txt').write_text('0.01 1 1 5.0\n')
        (root / 'RxPacketTrace.txt').write_text('% DL PHY trace header\n')
        (root / 'CellIdStats.txt').write_text('0.0 1 1 1\n')
        (root / 'DlPdcpStats.txt').write_text('% start end CellId IMSI RNTI LCID nTxPDUs TxBytes nRxPDUs RxBytes delay stdDev min max\n')
        (root / 'DlRlcStats.txt').write_text('% start end CellId IMSI RNTI LCID nTxPDUs TxBytes nRxPDUs RxBytes delay stdDev min max\n')
        return root

    def run_parser(self, root, output_root):
        args = [str(root), '--duration-s', '0.2']
        with patch('sys.argv', ['build_csv.py', *args]):
            build_csv.main()
        return output_root / 'csv'

    def test_header_only_bearer_traces_produce_empty_canonical_csv(self):
        with tempfile.TemporaryDirectory() as temp:
            outer = Path(temp); run = outer / 'run'; raw = self.make_raw(run / 'raw')
            output = self.run_parser(raw, run)
            with (output / 'bearer_intervals.csv').open() as stream:
                reader = csv.DictReader(stream)
                self.assertEqual(reader.fieldnames, build_csv.BEARER_FIELDS)
                self.assertEqual(list(reader), [])
            quality = json.loads((output / 'quality_report.json').read_text())
            self.assertEqual(quality['bearer_rows'], 0)
            self.assertTrue(quality['bearer_intervals_available'])
            self.assertEqual(quality['bearer_intervals_by_layer'], {'pdcp': 0, 'rlc': 0})

    def test_missing_required_bearer_trace_still_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp) / 'run'; raw = self.make_raw(run / 'raw')
            (raw / 'DlRlcStats.txt').unlink()
            with patch('sys.argv', ['build_csv.py', str(raw), '--duration-s', '0.2']):
                with self.assertRaises(FileNotFoundError):
                    build_csv.main()


if __name__ == '__main__':
    unittest.main()
