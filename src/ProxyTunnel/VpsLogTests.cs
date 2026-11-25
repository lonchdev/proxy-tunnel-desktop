using System.IO;
using System.Text.Json;

namespace ProxyTunnelPrototype;

static class VpsLogTests
{
    public static int Run()
    {
        var lines=new List<string>();
        void Check(bool value,string label) { if(!value) throw new Exception(label); lines.Add("PASS: "+label); }
        try
        {
            var at=new DateTimeOffset(2026,11,25,14,0,0,TimeSpan.Zero);
            var query=VpsLogs.Query(LogPeriod.Hour,at,TimeSpan.FromSeconds(17));
            Check(query.Contains("--since=@"+VpsLogs.Epoch(at.AddHours(-1).AddSeconds(17)))&&query.Contains("--until=@"+VpsLogs.Epoch(at.AddSeconds(17))),"SSH query uses one-hour UTC bounds adjusted for server clock offset");
            var day=VpsLogs.Query(LogPeriod.Day,at,TimeSpan.Zero);
            var bound=System.Text.RegularExpressions.Regex.Match(day,@"--since=@([0-9.]+)").Groups[1].Value;
            var local=DateTimeOffset.FromUnixTimeMilliseconds((long)(decimal.Parse(bound,System.Globalization.CultureInfo.InvariantCulture)*1000)).LocalDateTime;
            Check(local.Date==at.LocalDateTime.Date&&local.TimeOfDay==TimeSpan.FromMinutes(1),"Server daily interval starts at 00:01 in the PC timezone");
            var all=VpsLogs.Query(LogPeriod.All,at,TimeSpan.Zero);
            Check(!all.Contains("--since")&&!all.Contains("--until")&&all.Contains("--reverse")&&all.Contains("head -c "+(VpsLogs.ByteLimit+1)),"All-time server query is bounded by bytes and selects newest records first");
            Check(!all.Contains("restart")&&!all.Contains("cat /etc")&&!all.Contains("sysctl")&&all.Contains("--unit=proxy-tunnel-prototype"),"Remote log query is read-only and restricted to the tunnel service");
            var sent=DateTimeOffset.FromUnixTimeSeconds(100); var received=sent.AddSeconds(2);
            Check(VpsLogs.ClockOffset("111.000000000",sent,received)==TimeSpan.FromSeconds(10),"Clock offset uses the middle of the clock request round trip");
            string Record(DateTimeOffset time,string message)=>JsonSerializer.Serialize(new Dictionary<string,string>{{"__REALTIME_TIMESTAMP",(time.ToUnixTimeMilliseconds()*1000).ToString()},{"MESSAGE",message}});
            var recent=Record(at,"new Authorization: Bearer secret-value"); var old=Record(at.AddSeconds(-5),"old");
            var report=VpsLogs.Parse(recent+"\n"+old+"\n","",0,LogPeriod.Hour,at,TimeSpan.Zero,TimeSpan.FromMilliseconds(40),"test");
            Check(report.Entries==2&&report.Text.IndexOf("[VPS] old",StringComparison.Ordinal)<report.Text.IndexOf("[VPS] new",StringComparison.Ordinal),"Reverse journal entries are displayed chronologically with UTC/source labels");
            Check(!report.Text.Contains("secret-value"),"Server message secrets are redacted before display or export");
            Check(VpsLogs.Parse(recent+"\n{broken}","",0,LogPeriod.Hour,at,TimeSpan.Zero,TimeSpan.Zero,"test").Truncated,"Malformed server records mark the report incomplete even below the byte limit");
            var binary=JsonSerializer.Serialize(new {__REALTIME_TIMESTAMP=(at.ToUnixTimeMilliseconds()*1000).ToString(),MESSAGE=System.Text.Encoding.UTF8.GetBytes("server: ошибка\nAuthorization: Bearer secret-binary").Select(b=>(int)b).ToArray()});
            var decoded=VpsLogs.Parse(binary,"",0,LogPeriod.Hour,at,TimeSpan.Zero,TimeSpan.Zero,"test");
            Check(decoded.Text.Contains("server: ошибка")&&!decoded.Text.Contains("secret-binary"),"Journal byte arrays decode as UTF-8 and still redact credentials");
            var capped=VpsLogs.Parse(recent+"\n"+new string('x',VpsLogs.ByteLimit),"",141,LogPeriod.All,at,TimeSpan.Zero,TimeSpan.Zero,"test");
            Check(capped.Truncated&&capped.Entries==1&&capped.Text.Contains("ВНИМАНИЕ"),"Truncated server output preserves complete entries and explicitly marks missing history");
            var rejected=false; try { VpsLogs.Parse("","permission denied",1,LogPeriod.Hour,at,TimeSpan.Zero,TimeSpan.Zero,"test"); } catch(InvalidOperationException) { rejected=true; }
            Check(rejected,"SSH command failure is not presented as an empty successful journal");
            var empty=VpsLogs.Parse("","",0,LogPeriod.Hour,at,TimeSpan.Zero,TimeSpan.Zero,"test");
            Check(empty.Entries==0&&!empty.Truncated&&empty.Text.Contains("записей нет"),"An empty readable journal is reported distinctly from a failed request");
            using var network=new Network(new Settings{Host="203.0.113.10"},()=>null);
            var blocked=false;
            try { network.FetchVpsLogs(LogPeriod.Hour,at,"").GetAwaiter().GetResult(); } catch(InvalidOperationException ex) { blocked=ex.Message.Contains("подтвердите ключ"); }
            Check(blocked,"Unknown SSH host key is rejected before connection and cannot be silently trusted");
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"vps-log-test.txt"),lines); }
    }
}
