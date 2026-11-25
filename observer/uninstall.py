#!/usr/bin/env python3
"""Remove only the observer; preserve history and the tunnel service."""
import os
import pathlib
import sys
import importlib.util

spec = importlib.util.spec_from_file_location('observer_install',pathlib.Path(__file__).with_name('install.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
targets, run, SERVICE = installer.targets, installer.run, installer.SERVICE


def uninstall(root=pathlib.Path('/'), runner=run):
    base, unit = targets(root)
    runner(['systemctl','disable','--now',SERVICE],check=False)
    for path in (unit,base/'observer.py'):
        if path.exists():
            path.unlink()
    try:
        base.rmdir()
    except OSError:
        pass
    runner(['systemctl','daemon-reload'])


if __name__ == '__main__':
    try:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise RuntimeError('Root access on Linux is required')
        installer.verify(pathlib.Path(__file__).resolve().parent)
        uninstall()
        print('Observer removed. History preserved. Tunnel service and firewall unchanged.')
    except Exception as error:
        print('Removal failed: '+str(error),file=sys.stderr)
        sys.exit(1)
