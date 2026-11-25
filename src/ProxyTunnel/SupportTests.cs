using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace ProxyTunnelPrototype;

static class SupportTests
{
    public static int Run()
    {
        var lines=new List<string>();
        Directory.CreateDirectory(Settings.DataDir);
        var testFile=Path.Combine(Settings.DataDir,"proxy-test-"+Guid.NewGuid().ToString("N")+".json");
        Environment.SetEnvironmentVariable("PROXY_TUNNEL_TEST_PROXY_STORE",testFile);
        void Assert(bool value,string message) { if(!value) throw new Exception(message); lines.Add("PASS: "+message); }
        try
        {
            using var key=new ProxyValues(true);
            key.SetValue("ProxyEnable",1); key.SetValue("ProxyServer","127.0.0.1:10809"); key.SetValue("AutoConfigURL","http://127.0.0.1:8889/proxy.pac"); key.SetValue("ProxyOverride","original-bypass");
            ProxyLease.Apply(); Assert(ProxyLease.Owns(),"Browser proxy lease applied to isolated test key");
            ProxyLease.Release();
            Assert((key.GetValue("ProxyServer") as string)=="127.0.0.1:10809"&&(key.GetValue("AutoConfigURL") as string)=="http://127.0.0.1:8889/proxy.pac"&&(key.GetValue("ProxyOverride") as string)=="original-bypass","Previous proxy/PAC/bypass restored");
            ProxyLease.Apply(); key.SetValue("ProxyServer","external-change:99"); ProxyLease.Release();
            Assert((key.GetValue("ProxyServer") as string)=="external-change:99","Concurrent external proxy change preserved");
            ProxyLease.Apply(); key.SetValue("ProxyOverride","external-bypass"); ProxyLease.Release();
            Assert((key.GetValue("ProxyOverride") as string)=="external-bypass","External bypass change preserved while restoring owned proxy fields");
            ProxyLease.Apply(); File.WriteAllText(Path.Combine(Settings.DataDir,"proxy-lease.json"),"{broken"); ProxyLease.Release();
            Assert((key.GetValue("ProxyServer") as string)=="external-change:99"&&!File.Exists(Path.Combine(Settings.DataDir,"proxy-lease.json.bak")),"Damaged primary snapshot restored from atomic backup");
            var psi=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase)) psi.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory,"ProxyTunnel-Prototype.dll"));
            psi.ArgumentList.Add("--lease-fixture");
            using(var child=Process.Start(psi)!) { child.WaitForExit(); Assert(child.ExitCode==0,"Watchdog fixture started successfully"); }
            var timeout=Stopwatch.StartNew();
            while(timeout.ElapsedMilliseconds<6000&&ProxyLease.Owns()) Thread.Sleep(100);
            Assert((key.GetValue("ProxyServer") as string)=="external-change:99","Watchdog restored proxy after parent exit");
            WindowsNetwork.CheckDns("claude.ai").GetAwaiter().GetResult(); lines.Add("PASS: Windows DNS bypass-cache query");
            Assert(!string.IsNullOrWhiteSpace(WindowsNetwork.PhysicalInterface()),"Physical uplink detected");
            var testHost=Environment.GetEnvironmentVariable("PROXY_TUNNEL_VPS_TEST_HOST");
            if(!string.IsNullOrWhiteSpace(testHost))
            {
                var ping=WindowsNetwork.TcpPing(testHost,24443).GetAwaiter().GetResult();
                Assert(ping.HasValue,"Explicitly configured VPS TCP ping measured ("+ping+" ms)");
            }
            else lines.Add("SKIP: VPS TCP ping requires PROXY_TUNNEL_VPS_TEST_HOST");
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally
        {
            try { ProxyLease.Release(); } catch { }
            File.Delete(testFile);
            File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"support-test.txt"),lines);
        }
    }
}
