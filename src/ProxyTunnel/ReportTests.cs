using System.IO;
using System.IO.Compression;
using System.Net.Sockets;

namespace ProxyTunnelPrototype;

static class ReportTests
{
    public static int Run()
    {
        var lines=new List<string>();
        void Check(bool ok,string label) { if(!ok) throw new Exception(label); lines.Add("PASS: "+label); }
        try
        {
            var at=DateTimeOffset.Now;
            var server=new VpsLogReport("server entry",1,false,at);
            var combined=ReportBundle.Compose(LogPeriod.Hour,at,"pc entry",server,null);
            Check(combined.Contains("=== ПК ===")&&combined.Contains("=== VPS ===")&&combined.Contains("pc entry")&&combined.Contains("server entry")&&combined.Contains("1h"),"Combined clipboard report preserves PC and VPS sections with the same requested period");
            var partial=ReportBundle.Compose(LogPeriod.Hour,at,"pc entry",null,"Authorization: Bearer private-report-token");
            Check(partial.Contains("СЕРВЕРНЫЕ ЛОГИ НЕ ПОЛУЧЕНЫ")&&partial.Contains("pc entry")&&!partial.Contains("private-report-token"),"Unavailable VPS produces an explicit partial report without dropping PC logs or leaking error credentials");
            var root=Path.Combine(Settings.DataDir,"incidents-tests-"+Guid.NewGuid().ToString("N"));
            var store=new IncidentStore(root);
            var item=store.Begin("203.0.113.10",24443,"timeout","Wi-Fi",at);
            Check(store.Begin(item.Host,item.Port,"another error","",at.AddMinutes(1)).Id==item.Id,"Repeated failures in the same five-minute collection window coalesce into one incident");
            store.Begin(item.Host,item.Port,"same timestamp","",at,out var duplicateCreated);
            Check(!duplicateCreated,"Identical clock timestamps cannot start duplicate incident preparation jobs");
            store.Before(item,"before entry\nAuthorization: Bearer private-before-token");
            store.Append(new(1,at.AddSeconds(-1).LocalDateTime,LogSeverity.Info,"not after","a"));
            store.Append(new(2,at.AddSeconds(1).LocalDateTime,LogSeverity.Warning,"after entry\nAuthorization: Bearer private-after-token","b"));
            store.Append(new(3,at.AddMinutes(6).LocalDateTime,LogSeverity.Info,"too late","c"));
            var after=File.ReadAllText(Path.Combine(root,item.Id,"pc-after.log"));
            Check(after.Contains("after entry")&&!after.Contains("not after")&&!after.Contains("too late")&&!after.Contains("private-after-token"),"Incident tail contains only the after-window and redacts known secrets");
            Check(store.Due(item.Host,item.Port,at.AddMinutes(4))==null&&store.Due(item.Host,item.Port,at.AddMinutes(5))?.Id==item.Id&&store.Due("203.0.113.11",item.Port,at.AddHours(1))==null,"Server collection waits for the complete after-window and never targets another VPS");
            store.Failed(item,"offline",at.AddMinutes(5));
            Check(store.Due(item.Host,item.Port,at.AddMinutes(5))==null&&store.Due(item.Host,item.Port,at.AddMinutes(7))?.Id==item.Id,"Unavailable server snapshots remain pending with a retry delay");
            store.Received(item,server);
            Check(store.Due(item.Host,item.Port,at.AddHours(1))==null,"A completed server report is not fetched repeatedly");
            var reloaded=new IncidentStore(root);
            Check(reloaded.Latest?.Id==item.Id&&reloaded.Latest.ServerReceived&&reloaded.Latest.BeforeReady,"Incident metadata, PC capture state and downloaded VPS data survive an application restart");
            store.Begin(item.Host,item.Port,"next incident","",at.AddMinutes(6));
            var archive=Path.Combine(root,"saved.zip"); store.Export(item.Id,archive);
            using(var zip=ZipFile.OpenRead(archive))
            {
                var before=zip.GetEntry("pc-before.log")!; using var read=new StreamReader(before.Open()); var text=read.ReadToEnd();
                Check(zip.GetEntry("incident.json")!=null&&zip.GetEntry("pc-after.log")!=null&&zip.GetEntry("vps.log")!=null&&!text.Contains("private-before-token")&&text.Contains(item.Id),"Exported incident ZIP contains the selected incident rather than a newer one and excludes known secrets");
            }
            for(int i=1;i<=22;i++) store.Begin(item.Host,item.Port,"fault","",at.AddMinutes(10+i*6));
            Check(Directory.EnumerateDirectories(root).Count()<=20,"Local incident retention is bounded to twenty directories");
            var health=new TrafficHealth(); health.Failure(TimeSpan.Zero); health.Failure(TimeSpan.FromSeconds(1)); health.Failure(TimeSpan.FromSeconds(2));
            Check(health.Recent(TimeSpan.FromSeconds(3))==3&&health.Recent(TimeSpan.FromSeconds(100))==0,"Recent transport failures expire so a later healthy check can clear partial-failure status");
            Check(TrafficHealth.IsVpsFailure("dial tcp 203.0.113.10:24443: i/o timeout",item.Host,item.Port)&&!TrafficHealth.IsVpsFailure("dial tcp 192.168.1.3:7680: i/o timeout",item.Host,item.Port),"Only transport failures to the configured VPS count toward partial connectivity");
            Check(TrafficHealth.IsExpectedClose(new IOException("client close",new SocketException(10054)))&&!TrafficHealth.IsExpectedClose(new SocketException(10060)),"Connection reset/abort is distinguished from a true timeout");
            Check(Journal.Classify("ERROR lookup ipv6.msftconnecttest.com: empty result")==LogSeverity.Info&&Journal.Classify("ERROR dial tcp 203.0.113.10:24443: i/o timeout")==LogSeverity.Warning,"Expected IPv4-only connectivity probe misses do not hide actual VPS failures");
            var missing=VpsLogs.AddObserver(server,"PT_OBSERVER_NOT_INSTALLED\n","",0,at,TimeSpan.Zero,TimeSpan.Zero,"test");
            var failed=VpsLogs.AddObserver(server,"","permission denied",1,at,TimeSpan.Zero,TimeSpan.Zero,"test");
            Check(!missing.ObserverAvailable&&!missing.ObserverError&&failed.ObserverError&&failed.Text.Contains("server entry"),"Missing observer and a failed observer download are distinct; existing service logs are retained");
            var query=VpsLogs.Query(at.AddMinutes(-5),at.AddMinutes(5),TimeSpan.FromSeconds(2));
            Check(query.Contains("--since=@"+VpsLogs.Epoch(at.AddMinutes(-5).AddSeconds(2)))&&query.Contains("--until=@"+VpsLogs.Epoch(at.AddMinutes(5).AddSeconds(2))),"Automatic incident server query uses its exact ten-minute window and clock correction");
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"report-test.txt"),lines); }
    }
}
