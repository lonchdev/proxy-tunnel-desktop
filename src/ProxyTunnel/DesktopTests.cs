using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace ProxyTunnelPrototype;

internal static class DesktopTests
{
    public static int Run()
    {
        var lines=new List<string>(); MainWindow? window=null;
        void Check(bool condition,string label) { if(!condition) throw new Exception(label); lines.Add("PASS: "+label); }
        void Pump() { var frame=new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ContextIdle,new Action(()=>frame.Continue=false)); Dispatcher.PushFrame(frame); }
        try
        {
            Check(DesktopBehavior.AutoConnect(true,true,false),"New startup tasks automatically connect a configured server");
            Check(DesktopBehavior.AutoConnect(true,false,true),"Legacy enabled tasks without startup arguments also connect");
            Check(!DesktopBehavior.AutoConnect(false,true,true)&&!DesktopBehavior.AutoConnect(true,false,false),"An unconfigured server and an ordinary launch without autostart do not auto-connect");
            var app=new Application{ShutdownMode=ShutdownMode.OnExplicitShutdown};
            window=new MainWindow(new Settings()); window.Show(); Pump();
            Check(window.TrayVisibleForTest&&window.TrayConnectionForTest=="Подключиться","Real test window registers a visible tray icon and the disconnected menu action");
            window.WindowState=WindowState.Minimized; Pump();
            Check(window.IsVisible&&window.ShowInTaskbar&&window.TrayVisibleForTest,"Minimize keeps the window on the taskbar and retains its tray icon");
            window.Close(); Pump();
            Check(!window.IsVisible&&!window.ShowInTaskbar&&window.TrayVisibleForTest,"Close hides the window but does not dispose its tray icon");
            window.RestoreForTest(); Pump();
            Check(window.IsVisible&&window.ShowInTaskbar&&window.WindowState==WindowState.Normal,"Restore brings a closed-to-tray window back to the taskbar");
            window.Close(); window.RestoreForTest(); Pump();
            Check(window.IsVisible&&window.TrayVisibleForTest,"Repeated close and restore preserve a reachable running window");
            window.DisposeForTest(); window=null; app.Shutdown();
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { window?.DisposeForTest(); File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"desktop-test.txt"),lines); }
    }
}
