"""Reproduce the energy-before-mmwave DSO failure and test the actual linker fix."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from labcore.portable_build import shared_library_args, select_compilers

class LinkingTests(unittest.TestCase):
    def test_early_library_is_kept_for_late_dependency(self):
        _,cxx=select_compilers()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'energy.cc').write_text('extern "C" int energy(){return 7;}\n')
            (root/'mmwave.cc').write_text('extern "C" int energy(); extern "C" int mmwave(){return energy();}\n')
            (root/'main.cc').write_text('extern "C" int mmwave(); int main(){return mmwave()==7 ? 0 : 1;}\n')
            for name in ['energy','mmwave']:
                subprocess.run([cxx,'-shared','-fPIC',str(root/(name+'.cc')),'-o',str(root/('lib'+name+'.so'))],check=True,capture_output=True)
            libraries=[root/'libenergy.so',root/'libmmwave.so']
            base=[cxx,str(root/'main.cc'),'-Wl,--as-needed','-Wl,-rpath,'+str(root),'-o',str(root/'test')]
            broken=subprocess.run(base+list(map(str,libraries)),capture_output=True,text=True)
            self.assertNotEqual(broken.returncode,0)
            self.assertIn('energy',broken.stderr)
            fixed=subprocess.run(base+shared_library_args(libraries),capture_output=True,text=True)
            self.assertEqual(fixed.returncode,0,fixed.stderr)
            subprocess.run([str(root/'test')],check=True)

if __name__=='__main__':unittest.main()
