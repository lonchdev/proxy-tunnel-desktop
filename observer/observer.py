#!/usr/bin/env python3
# Proxy Tunnel observer - managed file
"""Read-only VPS observer; standard library only. No listeners or network changes."""
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

UTC = dt.timezone.utc
STATE = pathlib.Path('/var/lib/proxy-tunnel-observer')
UNIT = 'proxy-tunnel-prototype.service'


def clean(text):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'(?im)\b(Authorization|Proxy-Authorization)\s*:\s*[^\r\n]+', r'\1: [hidden]', text)
    text = re.sub(r'(?i)(https?|socks[45]?)://[^/\s@]+@', r'\1://[hidden]@', text)
    text = re.sub(r'(?i)([?&](?:access_token|refresh_token|id_token|token|key|api_key|code|client_secret|password|secret)=)[^&\s"\x27#]+', r'\1[hidden]', text)
    return re.sub(r'(?i)("(?:password|client_secret|access_token|refresh_token|id_token|api_key|secret)"\s*:\s*)"[^"]*"', r'\1"[hidden]"', text)


def utc_now():
    return dt.datetime.now(UTC).isoformat(timespec='milliseconds')


def sanitized(value):
    if isinstance(value,str):
        return clean(value)
    if isinstance(value,dict):
        return {key:('[hidden]' if key.lower() in ('password','secret','access_token','refresh_token','api_key','client_secret') else sanitized(item)) for key,item in value.items()}
    if isinstance(value,list):
        return [sanitized(item) for item in value]
    return value


class History:
    def __init__(self, root, max_bytes=200*1024*1024, days=14, segment_bytes=4*1024*1024):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes, self.days, self.segment_bytes = max_bytes, days, segment_bytes
        self.current = None

    def files(self):
        return sorted(p for p in self.root.glob('history-*.jsonl') if p.is_file() and not p.is_symlink())

    def append(self, record):
        if self.current is None or not self.current.exists() or self.current.stat().st_size >= self.segment_bytes:
            self.current = self.root / ('history-%020d.jsonl' % time.time_ns())
        with self.current.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(sanitized(record), ensure_ascii=True, separators=(',', ':')) + '\n')
        self.prune()

    def prune(self):
        files = self.files()
        total = sum(p.stat().st_size for p in files)
        cutoff = time.time() - self.days * 86400
        for path in files:
            if path == self.current:
                continue
            try:
                stat = path.stat()
                if stat.st_mtime < cutoff or total > self.max_bytes:
                    path.unlink()
                    total -= stat.st_size
            except FileNotFoundError:
                pass

    def sync(self):
        if self.current:
            with self.current.open('ab') as stream:
                stream.flush()
                os.fsync(stream.fileno())


def reversed_lines(path):
    with path.open('rb') as stream:
        stream.seek(0, os.SEEK_END)
        position, tail = stream.tell(), b''
        while position:
            size = min(65536, position)
            position -= size
            stream.seek(position)
            block = stream.read(size) + tail
            parts = block.split(b'\n')
            tail = parts[0]
            for line in reversed(parts[1:]):
                if line:
                    yield line
        if tail:
            yield tail


def export_history(root, since=None, until=None, byte_limit=1024*1024):
    root = pathlib.Path(root)
    if not root.is_dir():
        raise RuntimeError('Observer history is not available or not readable')
    result, size, truncated, skipped = [], 0, False, 0
    seen_cursors = set()
    paths = sorted((p for p in root.glob('history-*.jsonl') if p.is_file() and not p.is_symlink()), reverse=True)
    for path in paths:
        try:
            for line in reversed_lines(path):
                try:
                    record = json.loads(line)
                    stamp = dt.datetime.fromisoformat(record['time_utc']).timestamp()
                    if since is not None and stamp < since or until is not None and stamp > until:
                        continue
                    cursor = record.get('cursor')
                    if cursor and cursor in seen_cursors:
                        continue
                    if cursor:
                        seen_cursors.add(cursor)
                    message = '[observer] ' + json.dumps(sanitized(record), ensure_ascii=False, separators=(',', ':'))
                    entry = json.dumps({'__REALTIME_TIMESTAMP': str(int(stamp*1000000)), 'MESSAGE': message}, ensure_ascii=True)
                    length = len(entry.encode('utf-8')) + 1
                    if size + length > byte_limit:
                        truncated = True
                        break
                    result.append((stamp, entry))
                    size += length
                except (ValueError, TypeError, KeyError):
                    skipped += 1
        except FileNotFoundError:
            truncated = True  # File rotated during download; never silently claim completeness.
        if truncated:
            break
    return [entry for _, entry in sorted(result)], truncated, skipped


def read_text(path):
    return pathlib.Path(path).read_text(encoding='utf-8').strip()


def cpu_values(proc='/proc'):
    return [int(v) for v in read_text(pathlib.Path(proc)/'stat').splitlines()[0].split()[1:9]]


def cpu_delta(previous, current):
    values = [max(0, b-a) for a, b in zip(previous, current)]
    total = sum(values)
    if total == 0:
        return None
    return {'busy_percent': round(100*sum(values[i] for i in (0,1,2,5,6))/total, 2),
            'steal_percent': round(100*values[7]/total, 2), 'iowait_percent': round(100*values[4]/total, 2)}


def tcp_counters(proc='/proc'):
    result = {}
    for filename in ('snmp', 'netstat'):
        lines = read_text(pathlib.Path(proc)/'net'/filename).splitlines()
        for header, values in zip(lines[::2], lines[1::2]):
            name = header.split()[0].rstrip(':')
            for key, value in zip(header.split()[1:], values.split()[1:]):
                if key in ('OutSegs','InSegs','CurrEstab','RetransSegs','InErrs','EstabResets','ListenDrops','ListenOverflows','TCPSynRetrans','TCPTimeouts'):
                    result[name+'.'+key] = int(value)
    return result


def run(args):
    done = subprocess.run(args, capture_output=True, text=True, timeout=2, check=False)
    if done.returncode:
        raise RuntimeError(clean(done.stderr.strip())[:500] or 'command failed')
    return done.stdout


def service_state():
    output = run(['systemctl','show',UNIT,'--no-pager','--property=ActiveState,SubState,Result,NRestarts,MainPID,MemoryCurrent,MemoryPeak,CPUUsageNSec,ExecMainStatus,ExecMainCode,LimitNOFILE'])
    return dict(line.split('=',1) for line in output.splitlines() if '=' in line)


class JournalReader:
    def __init__(self, state):
        self.path = pathlib.Path(state)/'journal-cursor.json'
        try:
            self.cursor = json.loads(self.path.read_text())['cursor']
        except (OSError, ValueError, KeyError):
            self.cursor = None

    def read(self):
        args = ['journalctl','--quiet','--no-pager','--output=json','--output-fields=MESSAGE,PRIORITY','-n','+200','--unit='+UNIT]
        args += ['--after-cursor='+self.cursor] if self.cursor else ['--since=-10min']
        try:
            output = run(args)
        except RuntimeError:
            self.cursor = None
            raise
        rows = []
        for line in output.splitlines():
            try:
                entry = json.loads(line)
                stamp = dt.datetime.fromtimestamp(int(entry['__REALTIME_TIMESTAMP'])/1000000, UTC)
                message = entry.get('MESSAGE')
                rows.append((entry.get('__CURSOR'), {'time_utc':stamp.isoformat(), 'kind':'service_log',
                    'cursor':entry.get('__CURSOR'), 'priority':entry.get('PRIORITY'), 'message':clean(message)[:4096] if isinstance(message,str) else '[non-text message]'}))
            except (ValueError, KeyError, TypeError):
                continue
        if rows:
            self.cursor = rows[-1][0]
            # The collect loop persists this cursor only after writing the batch.
        return [row for _, row in rows], len(rows) >= 200

    def commit(self):
        temp = self.path.with_suffix('.tmp')
        with temp.open('w', encoding='utf-8') as stream:
            stream.write(json.dumps({'cursor':self.cursor}))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp,self.path)


class Connectivity:
    def __init__(self):
        self.result = {'status':'not_yet_checked'}
        self.worker = None
        self.last = -1e9

    def start_if_due(self):
        if time.monotonic()-self.last < 60 or self.worker and self.worker.is_alive():
            return
        self.last = time.monotonic()
        def check():
            checks = []
            for url in ('https://www.cloudflare.com/cdn-cgi/trace','https://checkip.amazonaws.com/'):
                started = time.monotonic()
                try:
                    with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=3) as response:
                        code = response.status
                    checks.append({'host':url.split('/')[2], 'http':code, 'ms':round((time.monotonic()-started)*1000)})
                except urllib.error.HTTPError as exc:
                    checks.append({'host':url.split('/')[2], 'http':exc.code, 'network_reachable':True})
                except Exception as exc:
                    checks.append({'host':url.split('/')[2], 'error':clean(str(exc))[:300]})
            self.result = {'time_utc':utc_now(),'checks':checks}
        self.worker = threading.Thread(target=check, daemon=True)
        self.worker.start()


def collect(root, interval=5, port=24443):
    history, journal, connectivity = History(root), JournalReader(root), Connectivity()
    previous_cpu = previous_tcp = None
    previous_service = None
    while True:
        started = time.monotonic()
        record = {'time_utc':utc_now(),'monotonic_ns':time.monotonic_ns(),'kind':'metrics','errors':[]}
        try:
            current = cpu_values()
            record['cpu'] = cpu_delta(previous_cpu,current) if previous_cpu else None
            previous_cpu = current
            record['loadavg'] = read_text('/proc/loadavg').split()[:3]
            memory = dict(line.split(':',1) for line in read_text('/proc/meminfo').splitlines())
            record['memory_kib'] = {key:int(memory[key].split()[0]) for key in ('MemTotal','MemAvailable','SwapTotal','SwapFree')}
            record['disk_free_bytes'] = shutil.disk_usage(root).free
            current_tcp = tcp_counters()
            record['tcp_system_counters'] = current_tcp
            record['tcp_system_delta'] = {key:max(0,value-previous_tcp.get(key,value)) for key,value in current_tcp.items() if not key.endswith('.CurrEstab')} if previous_tcp else None
            previous_tcp = current_tcp
            record['boot_id'] = read_text('/proc/sys/kernel/random/boot_id')
        except Exception as exc:
            record['errors'].append(clean(str(exc))[:500])
        try:
            service = service_state()
            record['service'] = service
            record['transport_port'] = port
            record['transport_tcp_listening'] = bool(run(['ss','-H','-lnt','sport = :'+str(port)]).strip())
            marker = (service.get('ActiveState'),service.get('NRestarts'),service.get('MainPID'))
            if previous_service is not None and marker != previous_service:
                history.append({'time_utc':utc_now(),'kind':'service_change','previous':previous_service,'current':marker})
            previous_service = marker
        except Exception as exc:
            record['errors'].append(clean(str(exc))[:500])
        connectivity.start_if_due()
        record['external_checks'] = connectivity.result
        record['external_check_pending'] = bool(connectivity.worker and connectivity.worker.is_alive())
        commit_cursor = False
        try:
            rows, capped = journal.read()
            for row in rows:
                history.append(row)
            commit_cursor = True
            if capped:
                record['errors'].append('Service journal batch reached 200 entries; remaining entries will be read on the next sample')
        except Exception as exc:
            record['errors'].append('Service journal: '+clean(str(exc))[:500])
        record['collector_work_ms'] = round((time.monotonic()-started)*1000)
        history.append(record)
        history.sync()
        if commit_cursor:
            journal.commit()
        time.sleep(max(0.1, interval-(time.monotonic()-started)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--export', action='store_true')
    parser.add_argument('--state', type=pathlib.Path, default=STATE)
    parser.add_argument('--from', dest='since', type=float)
    parser.add_argument('--until', type=float)
    parser.add_argument('--bytes', type=int, default=1024*1024)
    parser.add_argument('--port', type=int, default=24443)
    args = parser.parse_args()
    if args.export:
        rows, truncated, skipped = export_history(args.state,args.since,args.until,max(1024,min(args.bytes,2*1024*1024)))
        print('PT_OBSERVER_READY')
        print('PT_OBSERVER_TRUNCATED='+str(int(truncated)))
        print('PT_OBSERVER_SKIPPED='+str(skipped))
        for row in rows:
            print(row)
    else:
        if not 1024 <= args.port <= 65535:
            parser.error('port must be in 1024..65535')
        collect(args.state, port=args.port)


if __name__ == '__main__':
    main()
