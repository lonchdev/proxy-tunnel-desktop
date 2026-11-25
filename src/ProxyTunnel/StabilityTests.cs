using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace ProxyTunnelPrototype;

// Loopback transports, deterministic HTTP responses and an isolated journal only.
// These tests never create a TUN adapter or change firewall/proxy settings.
static class StabilityTests
{
    public static int Run()
    {
        var lines=new List<string>();
        void Assert(bool value,string label) { if(!value) throw new Exception(label); lines.Add("PASS: "+label); }
        try
        {
            var root=Path.Combine(Settings.DataDir,"journal-tests-"+Guid.NewGuid().ToString("N"));
            var journal=new Journal(root);
            journal.Add("problem A",LogSeverity.Critical,"A"); journal.Add("problem A again",LogSeverity.Critical,"A"); journal.Add("problem B",LogSeverity.Critical,"B");
            Assert(journal.UnreadCount==2&&journal.Snapshot().Single(r=>r.Key=="A").Repeats==2,"Badge counts distinct urgent problems; repeated lines grouped");
            journal.SetVisible(true);
            Assert(journal.UnreadCount==0&&journal.Snapshot().Count(r=>r.Severity==LogSeverity.Critical)==2,"Opening journal acknowledges badge and retains red rows");
            journal.Add("problem C",LogSeverity.Critical,"C");
            Assert(journal.UnreadCount==0,"Active journal considers new rows viewed");
            journal.SetVisible(false); journal.Add("problem A returned",LogSeverity.Critical,"A");
            Assert(journal.UnreadCount==1,"Problem recurring after leaving journal becomes unread");
            Assert(new Journal(root).UnreadCount==1,"Unread state survives restart");
            journal.SetVisible(true);
            Assert(new Journal(root).UnreadCount==0,"Acknowledgement survives restart");
            journal.Add("Authorization: Bearer secret-auth\nhttps://user:secret-pass@host/path?access_token=secret-token&code=secret-code\n{\"password\":\"secret-json\"}");
            Assert(!journal.ExportText().Contains("secret-"),"Authorization, URL credentials, tokens and JSON passwords redacted before storage/export");
            Assert(!string.Join("",Directory.EnumerateFiles(root,"journal-*.jsonl").Select(File.ReadAllText)).Contains("secret-"),"Disk journal contains no test secrets");
            for(int i=0;i<8;i++) journal.Add("ERROR connection to 192.168.0.103:7680 timeout");
            Assert(journal.Snapshot().Single(r=>r.Key=="local-update-peer-timeout").Severity==LogSeverity.Info,"Windows update peer timeouts remain informational");
            journal.SetVisible(false);
            for(int i=0;i<5;i++) journal.Add("ERROR repeated upstream connection failed");
            Assert(journal.UnreadCount==1,"Repeated external network errors escalate to an urgent issue");
            using(var network=new Network(new Settings())) { var before=network.Journal.Snapshot().Sum(r=>r.Repeats); network.ReportError(new Exception("test journal without event subscribers")); Assert(network.Journal.Snapshot().Sum(r=>r.Repeats)==before+1,"Network writes journal even without legacy event subscribers"); }

            var policy=new HealthPolicy();
            Assert(!policy.NeedsRestart(true,false)&&!policy.NeedsRestart(true,true)&&!policy.NeedsRestart(true,false)&&policy.NeedsRestart(true,false),"One failed health cycle preserves channel; success resets; two failures request recovery");
            Assert(new HealthPolicy().NeedsRestart(false,false),"Dead engine requests immediate recovery");
            var retry=new RetrySchedule(); var schedule=new List<int>();
            for(int i=0;i<8;i++) { retry.Failed(); schedule.Add((int)retry.Delay.TotalSeconds); }
            Assert(schedule.SequenceEqual(new[]{3,6,12,24,48,60,60,60}),"Reconnect backoff is 3/6/12/24/48/60 seconds and bounded"); retry.Reset(); Assert(retry.Failures==0,"Successful connection resets reconnect backoff");
            UplinkTests(Assert).GetAwaiter().GetResult();
            ProbeTests(Assert).GetAwaiter().GetResult();
            Assert(ProxyFront.Normalize("CONNECT ::1:443 HTTP/1.1\r\nHost: ::1:443\r\n\r\n")=="CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n","IPv6 CONNECT and Host authority normalized without touching payload");
            RelayTests(Assert).GetAwaiter().GetResult();
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"stability-test.txt"),lines); }
    }
    sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request,token); }
    static async Task UplinkTests(Action<bool,string> assert)
    {
        var wifi=new Uplink("wifi-id","Wi-Fi",8,"192.168.1.5","192.168.1.1");
        var policy=new UplinkStability();
        assert(!policy.Ready(null,TimeSpan.Zero)&&!policy.Ready(null,TimeSpan.FromHours(1)),"No physical uplink never becomes ready for a TUN launch");
        assert(!policy.Ready(wifi,TimeSpan.FromSeconds(10))&&!policy.Ready(wifi,TimeSpan.FromSeconds(12))&&policy.Ready(wifi,TimeSpan.FromSeconds(13)),"Physical uplink must remain unchanged for three seconds");
        assert(!policy.Ready(null,TimeSpan.FromSeconds(14))&&!policy.Ready(wifi,TimeSpan.FromSeconds(15))&&!policy.Ready(wifi,TimeSpan.FromSeconds(17)),"Wi-Fi disappearance and return restart the settling period");
        assert(!UplinkStability.RequiresRebind(wifi,wifi,false),"Unchanged physical uplink ignores unrelated adapter events");
        assert(UplinkStability.RequiresRebind(wifi,wifi,true),"Resume forces a fresh channel even with the same IP and interface");
        foreach(var next in new[]{wifi with {Addresses="192.168.1.6"},wifi with {Gateways="192.168.1.254"},wifi with {Index=9},wifi with {Id="ethernet-id"},wifi with {Name="Renamed Wi-Fi"}})
            if(!UplinkStability.RequiresRebind(wifi,next,false)) throw new Exception("Changed interface fingerprint did not require rebind");
        assert(true,"IP, gateway, interface ID/index and adapter name changes require fresh binding");
        assert(UplinkStability.RequiresRebind(wifi,null,false),"Lost physical link invalidates an existing channel binding");
        policy.Reset(); assert(!policy.Ready(wifi,TimeSpan.FromHours(1)),"Explicit resume reset requires settling again");

        var settings=new Settings{Host="203.0.113.10",ProvisionedHost="203.0.113.10",ProvisionedPort=24443,KillSwitch=false}; settings.SetSecret(Convert.ToBase64String(new byte[16]));
        using var network=new Network(settings,()=>null);
        var connect=network.Connect();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while(network.Phase!=NetworkPhase.WaitingForNetwork) { await Task.Delay(20,timeout.Token); if(connect.IsCompleted) throw new Exception("Offline controller exited early: "+network.State); }
        assert(network.CanCancel&&!network.Connected,"Real controller waits offline without launching a TUN adapter");
        await network.Disconnect().WaitAsync(timeout.Token); await connect.WaitAsync(timeout.Token);
        assert(network.Phase==NetworkPhase.Off&&!network.CanCancel&&!network.Connected,"Cancelling an offline connect completes and restores the Off state");
        await Task.Delay(3200,timeout.Token);
        assert(network.Phase==NetworkPhase.Off,"Network monitor cannot restart a manually cancelled connection");
    }
    static async Task ProbeTests(Action<bool,string> assert)
    {
        var calls=0;
        using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(++calls==1?new HttpResponseMessage(HttpStatusCode.ServiceUnavailable):new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("ip=203.0.113.10\nloc=GB")}))))
        {
            var result=await ExitProber.Probe(http,"203.0.113.10",CancellationToken.None);
            assert(calls==2&&result.UsedFallback,"Unavailable primary exit checker falls back without losing channel");
        }
        using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("198.51.100.11")}))))
        {
            var rejected=false; try { await ExitProber.Probe(http,"203.0.113.10",CancellationToken.None); } catch(TunnelSafetyException) { rejected=true; }
            assert(rejected,"Wrong exit IP is a safety failure and cannot be hidden by fallback");
        }
        using(var http=new HttpClient(new Handler(async(_,token)=> { await Task.Delay(Timeout.Infinite,token); return new HttpResponseMessage(HttpStatusCode.OK); })))
        {
            var unavailable=false; try { await ExitProber.Probe(http,"203.0.113.10",CancellationToken.None,TimeSpan.FromMilliseconds(20)); } catch(HttpRequestException) { unavailable=true; }
            assert(unavailable,"All checker timeouts report unavailable diagnostics");
            using var cancel=new CancellationTokenSource(25); var cancelled=false;
            try { await ExitProber.Probe(http,"203.0.113.10",cancel.Token); } catch(OperationCanceledException) { cancelled=true; }
            assert(cancelled,"User cancellation interrupts an in-flight exit check");
        }
    }
    static async Task Header(Stream stream,CancellationToken token)
    {
        var one=new byte[1]; var tail=0;
        for(int i=0;i<4096;i++) { if(await stream.ReadAsync(one,token)==0) throw new IOException("Early header EOF"); tail=(tail<<8)|one[0]; if(tail==0x0d0a0d0a) return; }
        throw new IOException("Header overflow");
    }
    static async Task RelayTests(Action<bool,string> assert)
    {
        foreach(var socks in new[]{false,true})
        {
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15)); var token=deadline.Token;
            using var backend=new TcpListener(IPAddress.Loopback,0); backend.Start();
            var upload=System.Security.Cryptography.RandomNumberGenerator.GetBytes(512*1024);
            var download=System.Security.Cryptography.RandomNumberGenerator.GetBytes(1024*1024);
            var server=Task.Run(async()=> {
                using var incoming=await backend.AcceptTcpClientAsync(token); using var wire=incoming.GetStream();
                if(socks) { var prefix=new byte[3]; await wire.ReadExactlyAsync(prefix,token); if(!prefix.SequenceEqual(new byte[]{5,1,0})) throw new IOException("SOCKS prefix"); await wire.WriteAsync(new byte[]{5,0},token); }
                else { await Header(wire,token); await wire.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"),token); }
                using var received=new MemoryStream(); await wire.CopyToAsync(received,token);
                if(!received.ToArray().SequenceEqual(upload)) throw new IOException("Upload modified");
                await wire.WriteAsync(download,token); incoming.Client.Shutdown(SocketShutdown.Send);
            },token);
            using var front=new ProxyFront(port:0,backendPort:((IPEndPoint)backend.LocalEndpoint).Port);
            front.Start();
            using var tcp=new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback,front.ListenPort,token); using var stream=tcp.GetStream();
            if(socks) { await stream.WriteAsync(new byte[]{5,1,0},token); var reply=new byte[2]; await stream.ReadExactlyAsync(reply,token); if(reply[1]!=0) throw new IOException("SOCKS response"); }
            else { await stream.WriteAsync(Encoding.ASCII.GetBytes("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),token); await Header(stream,token); }
            await stream.WriteAsync(upload,token); tcp.Client.Shutdown(SocketShutdown.Send);
            using var response=new MemoryStream(); await stream.CopyToAsync(response,token); await server;
            assert(response.ToArray().SequenceEqual(download),(socks?"SOCKS":"HTTP CONNECT")+": 512KB upload, send half-close and 1MB response complete without truncation");
        }
        foreach(var resetBackend in new[]{false,true})
        {
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(8)); var token=deadline.Token;
            var messages=new System.Collections.Concurrent.ConcurrentQueue<string>();
            using var backend=new TcpListener(IPAddress.Loopback,0); backend.Start();
            using var front=new ProxyFront(port:0,backendPort:((IPEndPoint)backend.LocalEndpoint).Port,log:messages.Enqueue);
            front.Start();
            using var tcp=new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback,front.ListenPort,token);
            if(resetBackend)
            {
                backend.Stop();
                await tcp.GetStream().WriteAsync(Encoding.ASCII.GetBytes("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),token);
            }
            else
            {
                await tcp.GetStream().WriteAsync(Encoding.ASCII.GetBytes("CONNECT "),token);
                await Task.Delay(50,token);
                tcp.Client.LingerState=new LingerOption(true,0); tcp.Dispose();
            }
            if(resetBackend) { while(messages.IsEmpty) await Task.Delay(20,token); }
            else await Task.Delay(300,token); // An EOF is also a valid, silent client close.
            assert(resetBackend?messages.Any(m=>m.StartsWith("[WARN]")):messages.All(m=>!m.StartsWith("[WARN]")),resetBackend?"Unavailable backend remains a warning":"Client reset is informational rather than a transport failure");
        }
    }
}
