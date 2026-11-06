"""Exporter failure boundaries; no experiment generation or network access."""
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from datasets.package_benchmark import export, ip_split, package_file, scrub
from checks.check_measured_package import safe_file


class MeasuredPackageTests(unittest.TestCase):
    def test_absolute_machine_paths_redacted(self):
        root=Path('/home/example/campaign')
        value={'source':str(root)+'/jobs/a/train.csv','command':['/usr/bin/g++','--output=/tmp/private/file'],'note':'numpy 2.0'}
        result=scrub(value,root)
        self.assertEqual(result['source'],'campaign:/jobs/a/train.csv')
        self.assertNotIn('/tmp/',str(result))
        self.assertNotIn('/usr/',str(result))
        self.assertEqual(result['note'],'numpy 2.0')

    def test_lossless_csv_with_embedded_newline(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'input.csv';target=root/'output.csv.gz'
            payload=b'id,value\n1,"a\nb"\n';source.write_bytes(payload)
            sha=hashlib.sha256(payload).hexdigest()
            result=package_file(source,target,sha,root)
            with gzip.open(target,'rb') as handle:
                self.assertEqual(handle.read(),payload)
            self.assertEqual(result['source_sha256'],sha)

    def test_changed_source_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'input.csv';source.write_text('changed')
            with self.assertRaisesRegex(ValueError,'Receipt hash mismatch'):
                package_file(source,root/'out.csv.gz','0'*64,root)

    def test_incomplete_campaign_not_published(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'campaign';source.mkdir()
            (source/'campaign.json').write_text(json.dumps({'status':'running','jobs':[]}))
            with self.assertRaisesRegex(ValueError,'fully completed'):
                export(source,root/'output')
            self.assertFalse((root/'output').exists())

    def test_split_seed_boundaries(self):
        for seed,role in ((4001,'train'),(4010,'train'),(5001,'validation'),(5005,'validation'),(6001,'test'),(6010,'test')):
            self.assertEqual(ip_split(seed),role)
        with self.assertRaises(ValueError):
            ip_split(900001)

    def test_path_traversal_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'data').write_text('data');(root/'link').symlink_to(root/'data')
            for name in ('../data','/tmp/data','link','x\\y'):
                with self.assertRaises(ValueError):
                    safe_file(root,name)


if __name__=='__main__':
    unittest.main()
