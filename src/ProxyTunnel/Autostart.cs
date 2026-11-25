using System.Diagnostics;
using System.Security.Principal;

namespace ProxyTunnelPrototype;

// The application requires elevation; an interactive logon task avoids a
// password and does not start the application in another user's session.
internal static class Autostart
{
    static string Name=>"ProxyTunnelPrototype-"+WindowsIdentity.GetCurrent().User!.Value;
    public static bool Enabled
    {
        get { if(TestContext.Enabled) return false; try { dynamic scheduler=Create(); return scheduler.GetFolder("\\").GetTask(Name).Enabled; } catch { return false; } }
    }
    static dynamic Create() { dynamic scheduler=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!; scheduler.Connect(); return scheduler; }
    public static void Set(bool enabled)
    {
        if(TestContext.Enabled) return;
        dynamic scheduler=Create(); dynamic folder=scheduler.GetFolder("\\");
        if(!enabled) { if(Enabled) folder.DeleteTask(Name,0); return; }
        dynamic task=scheduler.NewTask(0);
        task.RegistrationInfo.Description="Proxy Tunnel: запуск при входе владельца в Windows";
        var user=WindowsIdentity.GetCurrent().User!.Value;
        task.Principal.UserId=user; task.Principal.LogonType=3; task.Principal.RunLevel=1;
        dynamic trigger=task.Triggers.Create(9); trigger.UserId=user;
        dynamic action=task.Actions.Create(0); action.Path=Environment.ProcessPath!;
        action.WorkingDirectory=System.IO.Path.GetDirectoryName(Environment.ProcessPath!)!;
        task.Settings.DisallowStartIfOnBatteries=false; task.Settings.StopIfGoingOnBatteries=false;
        task.Settings.ExecutionTimeLimit="PT0S"; task.Settings.MultipleInstances=2;
        folder.RegisterTaskDefinition(Name,task,6,user,null,3,null);
    }
}
