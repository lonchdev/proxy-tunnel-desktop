import datetime as dt
import importlib.util
import json
import os
import pathlib
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('observer',pathlib.Path(__file__).with_name('observer.py'))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class ObserverTests(unittest.TestCase):
    def test_cpu_deltas_exclude_guest_double_count_and_measure_steal(self):
        before = [100,0,100,400,50,0,0,20]
        after = [110,0,120,440,60,0,0,40]
        self.assertEqual(observer.cpu_delta(before,after),{'busy_percent':30.0,'steal_percent':20.0,'iowait_percent':10.0})
        self.assertIsNone(observer.cpu_delta(before,before))

    def test_export_window_order_redaction_and_structured_json(self):
        with tempfile.TemporaryDirectory() as root:
            history = observer.History(root)
            base = dt.datetime(2026,11,25,12,0,tzinfo=dt.timezone.utc)
            for offset in (-10,0,10):
                history.append({'time_utc':(base+dt.timedelta(seconds=offset)).isoformat(),'kind':'service_log','message':'Authorization: Bearer private-token','password':'private-password'})
            rows, truncated, skipped = observer.export_history(root,base.timestamp(),(base+dt.timedelta(seconds=10)).timestamp())
            self.assertEqual(len(rows),2)
            self.assertFalse(truncated)
            self.assertEqual(skipped,0)
            self.assertNotIn('private-token',''.join(rows))
            self.assertNotIn('private-password',''.join(rows))
            self.assertEqual(json.loads(json.loads(rows[0])['MESSAGE'][len('[observer] '):])['password'],'[hidden]')
            self.assertLess(int(json.loads(rows[0])['__REALTIME_TIMESTAMP']),int(json.loads(rows[1])['__REALTIME_TIMESTAMP']))

    def test_rotation_size_and_age_preserve_unrelated_files(self):
        with tempfile.TemporaryDirectory() as root:
            sentinel = pathlib.Path(root)/'unrelated.txt'
            sentinel.write_text('keep')
            history = observer.History(root,max_bytes=1000,segment_bytes=1)
            for index in range(30):
                history.append({'time_utc':observer.utc_now(),'index':index,'value':'x'*80})
            self.assertLessEqual(sum(p.stat().st_size for p in history.files()),1000)
            first = history.files()[0]
            os.utime(first,(time.time()-16*86400,)*2)
            history.prune()
            self.assertFalse(first.exists())
            self.assertEqual(sentinel.read_text(),'keep')

    def test_cap_is_explicit_and_keeps_newest_complete_records(self):
        with tempfile.TemporaryDirectory() as root:
            history = observer.History(root)
            base = dt.datetime(2026,11,25,12,0,tzinfo=dt.timezone.utc)
            for index in range(20):
                history.append({'time_utc':(base+dt.timedelta(seconds=index)).isoformat(),'index':index})
            rows, truncated, skipped = observer.export_history(root,byte_limit=600)
            self.assertTrue(truncated)
            self.assertGreater(len(rows),0)
            self.assertLessEqual(sum(len(row.encode())+1 for row in rows),600)
            self.assertEqual(json.loads(json.loads(rows[-1])['MESSAGE'][len('[observer] '):])['index'],19)
            self.assertEqual(skipped,0)

    def test_cursor_forward_direction_and_persistence(self):
        with tempfile.TemporaryDirectory() as root:
            reader = observer.JournalReader(root)
            fixture = '\n'.join(json.dumps({'__CURSOR':str(i),'__REALTIME_TIMESTAMP':str(1000000+i),'MESSAGE':'row'+str(i)}) for i in (1,2))
            with patch.object(observer,'run',return_value=fixture) as run:
                rows, capped = reader.read()
                args = run.call_args.args[0]
                self.assertNotIn('--reverse',args)
                self.assertIn('+200',args)
                self.assertEqual([r['message'] for r in rows],['row1','row2'])
                self.assertFalse(capped)
            reader.commit()
            again = observer.JournalReader(root)
            self.assertEqual(again.cursor,'2')
            with patch.object(observer,'run',return_value='') as run:
                again.read()
                self.assertIn('--after-cursor=2',run.call_args.args[0])

    def test_bad_record_and_duplicate_cursor_are_not_silently_counted_twice(self):
        with tempfile.TemporaryDirectory() as root:
            history = observer.History(root)
            record = {'time_utc':observer.utc_now(),'kind':'service_log','cursor':'same','message':'test'}
            history.append(record)
            history.append(record)
            with history.current.open('a') as stream:
                stream.write('{broken\n')
            rows, truncated, skipped = observer.export_history(root)
            self.assertEqual(len(rows),1)
            self.assertEqual(skipped,1)
            self.assertFalse(truncated)

    def test_tcp_counters_are_labelled_system_wide(self):
        with tempfile.TemporaryDirectory() as root:
            net = pathlib.Path(root)/'net'
            net.mkdir()
            (net/'snmp').write_text('Tcp: OutSegs RetransSegs CurrEstab\nTcp: 100 4 2\n')
            (net/'netstat').write_text('TcpExt: ListenDrops TCPTimeouts\nTcpExt: 3 1\n')
            self.assertEqual(observer.tcp_counters(root),{'Tcp.OutSegs':100,'Tcp.RetransSegs':4,'Tcp.CurrEstab':2,'TcpExt.ListenDrops':3,'TcpExt.TCPTimeouts':1})


if __name__ == '__main__':
    unittest.main(verbosity=2)
