import errno
from pathlib import Path
import tempfile
import unittest
from labcore.ric_address import reserve_address

class AddressTests(unittest.TestCase):
    def test_busy_first_address_is_skipped(self):
        attempts=[]
        def probe(address):
            attempts.append(address)
            if len(attempts)==1:raise OSError(errno.EADDRINUSE,'busy')
        with tempfile.TemporaryDirectory() as folder:
            lease=reserve_address('run',lock_dir=Path(folder),probe=probe)
            self.assertEqual(lease.address,attempts[1]);self.assertNotEqual(lease.address,'127.0.0.1')
            lease.close()
    def test_active_lease_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            first=reserve_address('same',lock_dir=Path(folder),probe=lambda _:None)
            second=reserve_address('same',lock_dir=Path(folder),probe=lambda _:None)
            self.assertNotEqual(first.address,second.address)
            address=first.address;first.close();second.close()
            again=reserve_address('same',lock_dir=Path(folder),probe=lambda _:None)
            self.assertEqual(again.address,address);again.close()
    def test_permission_error_is_not_masked_as_port_conflict(self):
        def forbidden(_):raise OSError(errno.EPERM,'forbidden')
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(PermissionError):reserve_address('run',lock_dir=Path(folder),probe=forbidden)
    def test_explicit_busy_address_fails_without_killing_processes(self):
        def busy(_):raise OSError(errno.EADDRINUSE,'busy')
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RuntimeError):reserve_address('run','127.0.0.1',Path(folder),busy)
            with self.assertRaises(ValueError):reserve_address('run','192.0.2.1',Path(folder),busy)

if __name__=='__main__':unittest.main()
