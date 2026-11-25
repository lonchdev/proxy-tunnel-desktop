#!/usr/bin/env python3
"""Prepared installer. Execute on VPS only with the owner's separate approval."""
import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import uuid

SERVICE = 'proxy-tunnel-observer.service'
DESCRIPTION = 'Description=Proxy Tunnel independent observer'
MARKER = '# Proxy Tunnel observer - managed file'


def unit_text(port):
    return '''[Unit]
Description=Proxy Tunnel independent observer
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=true
SupplementaryGroups=systemd-journal
StateDirectory=proxy-tunnel-observer
StateDirectoryMode=0700
ExecStart=/usr/bin/python3 -I /opt/proxy-tunnel-observer/observer.py --state /var/lib/proxy-tunnel-observer --port %d
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
UMask=0077
MemoryMax=64M
CPUQuota=5%%
TasksMax=16
[Install]
WantedBy=multi-user.target
''' % port


def run(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Command failed: '+args[0])
    return result.returncode == 0


def verify(package):
    required = {'observer.py','install.py','uninstall.py'}
    found = set()
    for line in (package/'SHA256SUMS').read_text(encoding='ascii').splitlines():
        digest, name = line.split(None,1)
        name = name.strip()
        if name not in required or name in found or hashlib.sha256((package/name).read_bytes()).hexdigest() != digest.lower():
            raise RuntimeError('Package checksum mismatch')
        found.add(name)
    if found != required:
        raise RuntimeError('Incomplete package checksum list')


def targets(root):
    root = pathlib.Path(root)
    base = root/'opt/proxy-tunnel-observer'
    unit = root/'etc/systemd/system'/SERVICE
    for path in (root/'opt',base,base/'observer.py',root/'etc',root/'etc/systemd',root/'etc/systemd/system',unit):
        if path.is_symlink():
            raise RuntimeError('Refusing a symbolic link installation target')
    if (base/'observer.py').exists() and MARKER not in (base/'observer.py').read_text(encoding='utf-8'):
        raise RuntimeError('Unknown existing observer file')
    if unit.exists() and DESCRIPTION not in unit.read_text(encoding='utf-8'):
        raise RuntimeError('Unknown existing service unit')
    return base, unit


def atomic(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    try:
        temp.write_bytes(data)
        temp.chmod(mode)
        os.replace(temp,path)
    finally:
        if temp.exists():
            temp.unlink()


def install(package, port=24443, root=pathlib.Path('/'), runner=run):
    if not 1024 <= port <= 65535:
        raise ValueError('Invalid transport port')
    package = pathlib.Path(package)
    verify(package)
    compile((package/'observer.py').read_text(encoding='utf-8'),'observer.py','exec')
    base, unit = targets(root)
    script = base/'observer.py'
    old_script = script.read_bytes() if script.exists() else None
    old_unit = unit.read_bytes() if unit.exists() else None
    active = runner(['systemctl','is-active','--quiet',SERVICE],check=False)
    enabled = runner(['systemctl','is-enabled','--quiet',SERVICE],check=False)
    try:
        runner(['systemctl','stop',SERVICE],check=False)
        atomic(script,(package/'observer.py').read_bytes(),0o755)
        atomic(unit,unit_text(port).encode(),0o644)
        runner(['systemctl','daemon-reload'])
        runner(['systemctl','enable','--now',SERVICE])
        runner(['systemctl','is-active','--quiet',SERVICE])
    except Exception:
        runner(['systemctl','stop',SERVICE],check=False)
        if not enabled:
            runner(['systemctl','disable',SERVICE],check=False)
        for path, old, mode in ((script,old_script,0o755),(unit,old_unit,0o644)):
            if old is not None:
                atomic(path,old,mode)
            elif path.exists():
                path.unlink()
        runner(['systemctl','daemon-reload'],check=False)
        if active:
            runner(['systemctl','start',SERVICE],check=False)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=24443)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Run this installer as root on the Linux VPS, after approval')
    if not pathlib.Path('/usr/bin/python3').is_file() or not shutil.which('systemctl'):
        raise RuntimeError('Python 3 and systemd are required')
    version = subprocess.check_output(['systemctl','--version'],text=True,timeout=5).splitlines()[0].split()[1]
    if int(version) < 247:
        raise RuntimeError('systemd 247+ is required')
    install(pathlib.Path(__file__).resolve().parent,args.port)
    print('Observer installed. Tunnel service and firewall unchanged. History: /var/lib/proxy-tunnel-observer')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Installation failed: '+str(error),file=sys.stderr)
        sys.exit(1)
