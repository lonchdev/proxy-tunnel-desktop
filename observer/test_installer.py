import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer, remover = load('install'), load('uninstall')


def package(root):
    target = pathlib.Path(root)/'package'
    target.mkdir()
    for name in ('observer.py','install.py','uninstall.py'):
        (target/name).write_bytes((HERE/name).read_bytes())
    manifest = '\n'.join(hashlib.sha256((target/name).read_bytes()).hexdigest()+'  '+name for name in ('observer.py','install.py','uninstall.py'))
    (target/'SHA256SUMS').write_text(manifest,encoding='ascii')
    return target


class FakeSystemd:
    def __init__(self, fail_start=False, existing=False):
        self.calls, self.fail_start, self.existing = [], fail_start, existing

    def __call__(self,args,check=True):
        self.calls.append(args)
        if args[1] in ('is-active','is-enabled') and not check:
            return self.existing
        if args[1] == 'enable' and self.fail_start:
            raise RuntimeError('simulated start failure')
        return True


class InstallerTests(unittest.TestCase):
    def test_install_is_scoped_and_uses_resource_limits(self):
        with tempfile.TemporaryDirectory() as root:
            pkg, server, runner = package(root), pathlib.Path(root)/'server', FakeSystemd()
            installer.install(pkg,24443,server,runner)
            self.assertIn('--port 24443',(server/'etc/systemd/system'/installer.SERVICE).read_text())
            self.assertIn('CPUQuota=5%',(server/'etc/systemd/system'/installer.SERVICE).read_text())
            self.assertIn('MemoryMax=64M',(server/'etc/systemd/system'/installer.SERVICE).read_text())
            self.assertTrue(all('proxy-tunnel-prototype.service' not in call for call in runner.calls))
            self.assertFalse((server/'etc/sysctl.conf').exists())

    def test_bad_checksum_does_not_start_services_or_write_targets(self):
        with tempfile.TemporaryDirectory() as root:
            pkg, server, runner = package(root), pathlib.Path(root)/'server', FakeSystemd()
            (pkg/'observer.py').write_text('tampered')
            with self.assertRaises(RuntimeError):
                installer.install(pkg,24443,server,runner)
            self.assertFalse(server.exists())
            self.assertEqual(runner.calls,[])

    def test_unknown_existing_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            pkg, server, runner = package(root), pathlib.Path(root)/'server', FakeSystemd()
            base = server/'opt/proxy-tunnel-observer'
            base.mkdir(parents=True)
            (base/'observer.py').write_text('unrelated application')
            with self.assertRaises(RuntimeError):
                installer.install(pkg,24443,server,runner)
            self.assertEqual((base/'observer.py').read_text(),'unrelated application')
            self.assertEqual(runner.calls,[])

    def test_failure_rolls_back_previous_files_and_restores_observer(self):
        with tempfile.TemporaryDirectory() as root:
            pkg, server = package(root), pathlib.Path(root)/'server'
            installer.install(pkg,24443,server,FakeSystemd())
            script, unit = server/'opt/proxy-tunnel-observer/observer.py', server/'etc/systemd/system'/installer.SERVICE
            before = script.read_bytes(), unit.read_bytes()
            runner = FakeSystemd(fail_start=True,existing=True)
            with self.assertRaises(RuntimeError):
                installer.install(pkg,24444,server,runner)
            self.assertEqual((script.read_bytes(),unit.read_bytes()),before)
            self.assertIn(['systemctl','start',installer.SERVICE],runner.calls)

    def test_uninstall_preserves_history_and_other_services(self):
        with tempfile.TemporaryDirectory() as root:
            pkg, server = package(root), pathlib.Path(root)/'server'
            installer.install(pkg,24443,server,FakeSystemd())
            history = server/'var/lib/proxy-tunnel-observer/history-test.jsonl'
            history.parent.mkdir(parents=True)
            history.write_text('keep history')
            runner = FakeSystemd()
            remover.uninstall(server,runner)
            self.assertEqual(history.read_text(),'keep history')
            self.assertFalse((server/'etc/systemd/system'/installer.SERVICE).exists())
            self.assertTrue(all('proxy-tunnel-prototype.service' not in call for call in runner.calls))


if __name__ == '__main__':
    unittest.main(verbosity=2)
