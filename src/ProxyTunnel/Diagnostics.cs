using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using Renci.SshNet;

namespace ProxyTunnelPrototype;

static class Diagnostics
{
    public static int Run(string configPath)
    {
        var report=new List<string>();
        Process? engine=null;
        var conf=Path.Combine(Settings.DataDir,"diagnostic-client.json");
        Directory.CreateDirectory(Settings.DataDir);
        try
        {
            var s=JsonSerializer.Deserialize<Settings>(File.ReadAllText(configPath))!;
            report.Add("Endpoint: "+s.Host+":"+s.ServerPort);
            var info=new ConnectionInfo(s.Host,s.SshPort,s.AdminUser,new PrivateKeyAuthenticationMethod(s.AdminUser,new PrivateKeyFile(s.KeyPath))){Timeout=TimeSpan.FromSeconds(20)};
            using var ssh=new SshClient(info);
            ssh.HostKeyReceived+=(_,e)=>e.CanTrust=s.HostKeys.TryGetValue(s.Host+":"+s.SshPort,out var known)&&known==e.FingerPrintSHA256;
            ssh.Connect();
            using(var cmd=ssh.CreateCommand("systemctl status proxy-tunnel-prototype --no-pager -l; ss -lntup 'sport = :24443'; ufw status; journalctl -u proxy-tunnel-prototype -n 12 --no-pager"))
            { cmd.CommandTimeout=TimeSpan.FromSeconds(20); report.Add(cmd.Execute()); report.Add(cmd.Error); }
            using(var cmd=ssh.CreateCommand("printf 'IPv6 default route: '; ip -6 route show default; if command -v curl >/dev/null; then curl -6 -sS --connect-timeout 4 --max-time 6 https://api64.ipify.org 2>&1; fi")) { cmd.CommandTimeout=TimeSpan.FromSeconds(10); report.Add(cmd.Execute()); }
            // Compare secrets in memory only; never output either secret.
            string remote;
            using(var cmd=ssh.CreateCommand("cat /etc/proxy-tunnel-prototype/config.json")) remote=cmd.Execute();
            using var doc=JsonDocument.Parse(remote);
            var remoteKey=doc.RootElement.GetProperty("inbounds")[0].GetProperty("password").GetString();
            var key=s.ReadSecret(); report.Add("Local/server secret match: "+(key==remoteKey));
            using(var tcp=new TcpClient())
            {
                try { tcp.ConnectAsync(s.Host,s.ServerPort).WaitAsync(TimeSpan.FromSeconds(6)).GetAwaiter().GetResult(); report.Add("Remote TCP: connected"); }
                catch(Exception ex) { report.Add("Remote TCP: "+ex.GetType().Name+" "+ex.Message); }
            }
            using var n=new Network(s); n.Extract();
            File.WriteAllText(conf,ConfigBuilder.Client(s,key,false,WindowsNetwork.PhysicalInterface()));
            var psi=new ProcessStartInfo(n.Engine){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true,RedirectStandardOutput=true};
            foreach(var a in new[]{"run","-c",conf}) psi.ArgumentList.Add(a);
            engine=new Process{StartInfo=psi};
            var errors=new List<string>(); engine.ErrorDataReceived+=(_,e)=> { if(e.Data!=null) lock(errors) errors.Add(e.Data); };
            engine.Start(); engine.BeginErrorReadLine();
            using var front=new ProxyFront(); front.Start();
            Thread.Sleep(1500);
            report.Add("Engine running: "+!engine.HasExited);
            using(var tcp=new TcpClient())
            {
                try { tcp.ConnectAsync("127.0.0.1",ConfigBuilder.PortBase).WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult(); report.Add("Local TCP: connected"); }
                catch(Exception ex) { report.Add("Local TCP: "+ex.GetType().Name+" "+ex.Message); }
            }
            using(var http=new HttpClient(new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+ConfigBuilder.PortBase)}){Timeout=TimeSpan.FromSeconds(15)})
            {
                try { report.Add("Encrypted exit: "+http.GetStringAsync("https://api.ipify.org").GetAwaiter().GetResult().Trim()); }
                catch(Exception ex) { report.Add("Encrypted exit: "+ex); }
            }
            using var forward=new ForwardedPortLocal("127.0.0.1",(uint)(ConfigBuilder.PortBase+1),"127.0.0.1",8873);
            ssh.AddForwardedPort(forward); forward.Start();
            foreach(var port in new[]{ConfigBuilder.PortBase,ConfigBuilder.PortBase+1,ConfigBuilder.PortBase+2})
            {
                using var client=new HttpClient(new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+port),AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(12)};
                foreach(var url in new[]{"https://claude.ai/cdn-cgi/trace","https://chatgpt.com/","https://www.youtube.com/generate_204","https://web.telegram.org/"})
                {
                    try { var watch=Stopwatch.StartNew(); using var response=client.GetAsync(url,HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult(); report.Add($"PATH {port}: {url} HTTP {(int)response.StatusCode} ({watch.ElapsedMilliseconds} ms)"); }
                    catch(Exception ex) { report.Add($"PATH {port}: {url} FAILED {ex.GetBaseException().Message}"); }
                }
            }
            forward.Stop();
            lock(errors) report.AddRange(errors.TakeLast(25));
            return 0;
        }
        catch(Exception ex) { report.Add("FAILED: "+ex); return 1; }
        finally
        {
            try { if(engine!=null&&!engine.HasExited) { engine.Kill(true); engine.WaitForExit(5000); } engine?.Dispose(); } catch { }
            if(File.Exists(conf)) File.Delete(conf);
            File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"diagnostic.txt"),report);
        }
    }
}
