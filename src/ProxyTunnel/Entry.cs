using System.IO;
using System.Diagnostics;
using System.Net;
using System.Windows;
using System.Windows.Threading;

namespace ProxyTunnelPrototype;

public static class Entry
{
    [STAThread]
    public static int Main(string[] args)
    {
        if(args.Contains("--disable-kill-switch"))
        {
            try { KillSwitch.Disarm(); MessageBox.Show("Блокировка прямого интернета выключена.","Proxy Tunnel"); return 0; }
            catch(Exception ex) { MessageBox.Show(ex.Message,"Proxy Tunnel"); return 1; }
        }
        if(args.Contains("--proxy-watchdog")) return ProxyLease.Watch(args.Last());
        if(args.Contains("--support-test")) return SupportTests.Run();
        if(args.Contains("--privacy-test")) return PrivacyTests.Run();
        if(args.Contains("--lease-fixture")) { ProxyLease.Apply(); Thread.Sleep(400); return 0; }
        if(args.Contains("--self-test")) return SelfTest();
        if(args.Contains("--diagnose")) return Diagnostics.Run(args.Last());
        if(args.Contains("--channel-test"))
        {
            var report=Path.Combine(AppContext.BaseDirectory,"channel-test.txt");
            try
            {
                var s=System.Text.Json.JsonSerializer.Deserialize<Settings>(File.ReadAllText(args.Last()))!;
                using var n=new Network(s);
                File.WriteAllText(report,n.CheckChannel().GetAwaiter().GetResult()); return 0;
            }
            catch(Exception e) { File.WriteAllText(report,e.ToString()); return 1; }
        }
        if(args.Contains("--network-test")) return IntegrationTests.Run();
        if(args.Contains("--stability-test")) return StabilityTests.Run();
        if(args.Contains("--log-period-test")) return LogPeriodTests.Run();
        if(args.Contains("--vps-log-test")) return VpsLogTests.Run();
        if(args.Contains("--reports-test")) return ReportTests.Run();
        if(args.Contains("--probe")) return Probe();
        using var mutex=new Mutex(true,"Local\\ProxyTunnelPrototype.UI",out var first);
        if(!first) { MessageBox.Show("Proxy Tunnel уже запущен. Откройте его через значок в области уведомлений."); return 0; }
        try
        {
            string? recoveryProblem=null;
            try { ProxyLease.Recover(); } catch(Exception ex) { recoveryProblem=ex.Message; }
            var app=new Application();
            app.DispatcherUnhandledException+=(_,e)=> { MessageBox.Show(e.Exception.Message,"Proxy Tunnel"); e.Handled=true; };
            var window=new MainWindow(Settings.Load(),args.Contains("--render-preview"));
            if(recoveryProblem!=null) window.ReportStartupProblem(recoveryProblem);
            if(args.Contains("--render-preview")) window.ContentRendered+=(_,_)=> {
                window.RenderPages(args.Last()); window.Close();
            };
            return app.Run(window);
        }
        catch(Exception e) { MessageBox.Show(e.Message,"Proxy Tunnel"); return 1; }
    }
    static int Probe()
    {
        var path=Path.Combine(AppContext.BaseDirectory,"probe-result.txt");
        try
        {
            using var n=new Network(Settings.Load());
            n.ConfirmHost=(_,_)=>false; // Read-only diagnostics never silently trust an unknown server.
            File.WriteAllText(path,n.Probe("").GetAwaiter().GetResult()); return 0;
        }
        catch(Exception e) { File.WriteAllText(path,"FAILED: "+e.Message); return 1; }
    }
    static int SelfTest()
    {
        var lines=new List<string>();
        try
        {
            var s=new Settings{Host="203.0.113.10"}; s.Validate();
            using var n=new Network(s); n.Extract();
            var key=Convert.ToBase64String(new byte[16]);
            foreach(var mode in new[]{true,false})
            foreach(var tun in new[]{true,false})
            foreach(var physical in new[]{null,WindowsNetwork.PhysicalInterface()}.Distinct())
            {
                s.AllTraffic=mode;
                var path=Path.Combine(AppContext.BaseDirectory,"check.json");
                File.WriteAllText(path,ConfigBuilder.Client(s,key,tun,physical));
                var info=new ProcessStartInfo(n.Engine){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true};
                foreach(var a in new[]{"check","-c",path}) info.ArgumentList.Add(a);
                using var p=Process.Start(info)!; var error=p.StandardError.ReadToEnd(); p.WaitForExit(); File.Delete(path);
                if(p.ExitCode!=0) throw new Exception(error);
                lines.Add($"PASS: config all={mode} tun={tun} physical={physical!=null}");
            }
            s.SetSecret("secret-test"); if(s.ReadSecret()!="secret-test") throw new Exception("DPAPI roundtrip failed");
            lines.Add("PASS: Windows protected storage");
            s.ExtraDomains="https://bad.example";
            try { s.Validate(); throw new InvalidOperationException("Domain validator accepted URL"); } catch(Exception e) when(e is not InvalidOperationException) { }
            lines.Add("PASS: domain validation");
            File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"self-test.txt"),lines); return 0;
        }
        catch(Exception e) { lines.Add("FAILED: "+e); File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"self-test.txt"),lines); return 1; }
    }
}
