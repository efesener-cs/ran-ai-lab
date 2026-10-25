import tempfile
import unittest
from pathlib import Path
from discover_sources import identify, discover

class DiscoveryTests(unittest.TestCase):
    def test_version_filter_and_override(self):
        with tempfile.TemporaryDirectory() as temp:
            tree=Path(temp)/'mounted/flexric'
            (tree/'build').mkdir(parents=True)
            monitor=tree/'examples/xApp/c/monitor/xapp_kpm_moni.c'
            monitor.parent.mkdir(parents=True);monitor.touch()
            cache=tree/'build/CMakeCache.txt'
            cache.write_text('E2AP_VERSION:STRING=E2AP_V1\nKPM_VERSION:STRING=KPM_V3_00\n')
            self.assertTrue(identify(tree,'flexric'))
            self.assertEqual(discover('flexric',tree),tree.resolve())
            cache.write_text('E2AP_VERSION:STRING=E2AP_V2\nKPM_VERSION:STRING=KPM_V3_00\n')
            with self.assertRaises(RuntimeError): discover('flexric',tree)
    def test_ns3_requires_kpm3_and_built_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            tree=Path(temp)
            marker=tree/'contrib/oran-interface/model/oran-interface.cc'
            marker.parent.mkdir(parents=True);marker.write_text('ActionDefinition-Format4')
            self.assertFalse(identify(tree,'ns3'))
            (tree/'build/include/ns3').mkdir(parents=True)
            (tree/'build/lib').mkdir()
            self.assertTrue(identify(tree,'ns3'))
    def test_stale_cache_is_not_used_as_source_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'actual'
            (source/'build').mkdir(parents=True)
            monitor=source/'examples/xApp/c/monitor/xapp_kpm_moni.c'
            monitor.parent.mkdir(parents=True);monitor.touch()
            (source/'build/CMakeCache.txt').write_text(
                'E2AP_VERSION:STRING=E2AP_V1\nKPM_VERSION:STRING=KPM_V3_00\n'
                'CMAKE_HOME_DIRECTORY:INTERNAL=/work/flexric\n')
            self.assertEqual(discover('flexric',source),source.resolve())

if __name__=='__main__':unittest.main()
