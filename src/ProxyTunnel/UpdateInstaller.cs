using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace ProxyTunnelPrototype;

internal static class UpdateInstaller
{
    internal static void Replace(string target,string payload,string backup,string expectedPayload,string expectedOld)
    {
        if(!Updates.Hash(payload).Equals(expectedPayload,StringComparison.OrdinalIgnoreCase)||!Updates.Hash(target).Equals(expectedOld,StringComparison.OrdinalIgnoreCase)) throw new IOException("Файлы изменились после проверки обновления.");
        var next=target+".update-new";
        if(File.Exists(next)) throw new IOException("В папке остался файл другой установки: "+Path.GetFileName(next));
        try
        {
            File.Copy(payload,next,false);
            if(!Updates.Hash(next).Equals(expectedPayload,StringComparison.OrdinalIgnoreCase)) throw new IOException("Не удалось проверить записанный EXE.");
            if(!File.Exists(backup)) File.Copy(target,backup,false);
            if(!Updates.Hash(backup).Equals(expectedOld,StringComparison.OrdinalIgnoreCase)) throw new IOException("Резервная копия не прошла проверку.");
            File.Move(next,target,true);
        }
        finally { if(File.Exists(next)) File.Delete(next); }
    }
    internal static void Rollback(string target,string backup,string oldHash)
    {
        if(!Updates.Hash(backup).Equals(oldHash,StringComparison.OrdinalIgnoreCase)) throw new IOException("Резервная копия повреждена; блокировка сохраняется.");
        var next=target+".rollback-new"; File.Copy(backup,next,true);
        if(!Updates.Hash(next).Equals(oldHash,StringComparison.OrdinalIgnoreCase)) throw new IOException("Ошибка записи прежней версии.");
        File.Move(next,target,true);
    }
    internal static void WhenUnlocked(Action change)
    {
        var timer=Stopwatch.StartNew();
        while(true)
        {
            try { change(); return; }
            catch(Exception ex) when((ex is IOException or UnauthorizedAccessException)&&timer.Elapsed<TimeSpan.FromSeconds(10)) { Thread.Sleep(200); }
        }
    }
    static Process Launch(string target)
    {
        var start=new ProcessStartInfo(target){UseShellExecute=false,WorkingDirectory=Path.GetDirectoryName(target)!,CreateNoWindow=false};
        return Process.Start(start)??throw new IOException("Не удалось запустить приложение.");
    }
    public static int Run(string id)
    {
        UpdateTransaction? transaction=null; Process? newApp=null; var replaced=false;
        using var mutex=new Mutex(false,"Local\\ProxyTunnel.UpdateInstaller"); var ownsMutex=false;
        try
        {
            try { ownsMutex=mutex.WaitOne(0); } catch(AbandonedMutexException) { ownsMutex=true; }
            if(!ownsMutex) throw new IOException("Другой установщик ещё работает.");
            var folder=Updates.DirectoryFor(id);
            transaction=JsonSerializer.Deserialize<UpdateTransaction>(File.ReadAllText(Path.Combine(folder,"transaction.json")))??throw new IOException("Не найден план обновления.");
            if(transaction.Id!=id||Path.GetFileName(transaction.Target)!="ProxyTunnel-Prototype.exe"||!Path.IsPathFullyQualified(transaction.Target)) throw new IOException("Недопустимая цель обновления.");
            using var parent=Process.GetProcessById(transaction.ParentId);
            if(parent.StartTime.ToUniversalTime().Ticks!=transaction.ParentStart||!string.Equals(Path.GetFullPath(parent.MainModule!.FileName),Path.GetFullPath(transaction.Target),StringComparison.OrdinalIgnoreCase)) throw new IOException("Не подтверждён процесс владельца обновления.");
            if(!Updates.Hash(transaction.Target).Equals(transaction.ParentHash,StringComparison.OrdinalIgnoreCase)||!Updates.Hash(Environment.ProcessPath!).Equals(transaction.ParentHash,StringComparison.OrdinalIgnoreCase)) throw new IOException("Не подтверждён исходный EXE установщика.");
            var manifest=Updates.Verify(File.ReadAllBytes(Path.Combine(folder,"update.json")),File.ReadAllBytes(Path.Combine(folder,"update.sig")));
            if(!transaction.Rollback)
            {
                if(Version.Parse(manifest.Version)<=typeof(Updates).Assembly.GetName().Version) throw new IOException("Понижение или повторная установка версии запрещены.");
                Updates.ExtractVerified(folder,manifest);
            }
            else if(!Updates.Hash(Path.Combine(folder,"previous.exe")).Equals(transaction.OldHash,StringComparison.OrdinalIgnoreCase)) throw new IOException("Неверная резервная копия.");
            AtomicFile.Write(Path.Combine(folder,"ready"),"ready");
            var waiting=Stopwatch.StartNew();
            while(!parent.WaitForExit(100))
            {
                if(File.Exists(Path.Combine(folder,"abort"))) return 0;
                if(waiting.Elapsed>TimeSpan.FromSeconds(60)) throw new IOException("Приложение не завершилось; замена файлов не началась.");
            }
            if(!Updates.Pending||Updates.Read().Id!=id||Updates.Read().Step!="blocked"||!KillSwitch.Armed) throw new IOException("Блокировка обновления не подтверждена; замена запрещена.");
            KillSwitch.ArmUpdateBlock();
            if(transaction.Rollback) WhenUnlocked(()=>Rollback(transaction.Target,Path.Combine(folder,"previous.exe"),transaction.OldHash));
            else WhenUnlocked(()=>Replace(transaction.Target,Path.Combine(folder,"new.exe"),Path.Combine(folder,"previous.exe"),manifest.ExeSha256,transaction.OldHash));
            replaced=true; transaction.Step=transaction.Rollback?"rolled-back":"installed"; Updates.Save(transaction);
            newApp=Launch(transaction.Target);
            var timer=Stopwatch.StartNew();
            while(timer.Elapsed<TimeSpan.FromMinutes(3))
            {
                if(File.Exists(Path.Combine(folder,"complete"))) return 0;
                if(newApp.HasExited) throw new IOException("Новая версия завершилась до подтверждения рабочего туннеля.");
                Thread.Sleep(500);
            }
            // An offline VPS does not prove the binary is broken. Keep its UI
            // available for recovery; never unblock traffic on a timer.
            transaction.Error="Туннель не подтверждён за 3 минуты. Защита остаётся включённой; повторите подключение.";
            AtomicFile.Write(Path.Combine(folder,"status.txt"),transaction.Error); return 2;
        }
        catch(Exception ex)
        {
            try
            {
                if(transaction!=null&&Updates.Pending&&Updates.Read().Id==id)
                {
                    transaction.Error=ex.GetBaseException().Message;
                    if(replaced)
                    {
                        KillSwitch.ArmUpdateBlock();
                        if(newApp is {HasExited:false}) { newApp.Kill(true); newApp.WaitForExit(10000); }
                        WhenUnlocked(()=>Rollback(transaction.Target,Path.Combine(Updates.DirectoryFor(id),"previous.exe"),transaction.OldHash));
                        transaction.Step="rolled-back"; Updates.Save(transaction); Launch(transaction.Target);
                    }
                    else { Updates.Save(transaction); var alive=false; try { using var original=Process.GetProcessById(transaction.ParentId); alive=!original.HasExited&&original.StartTime.ToUniversalTime().Ticks==transaction.ParentStart; } catch { } if(!alive) Launch(transaction.Target); }
                }
            }
            catch(Exception rollback) { ex=new IOException(ex.Message+"\nОткат: "+rollback.Message,rollback); }
            MessageBox.Show("Обновление не завершено. Прямой интернет автоматически не включается.\n\n"+ex.GetBaseException().Message,"Proxy Tunnel · обновление"); return 1;
        }
        finally { newApp?.Dispose(); if(transaction!=null) try { AtomicFile.Write(Path.Combine(Updates.DirectoryFor(transaction.Id),"installer.done"),"done"); } catch { } if(ownsMutex) mutex.ReleaseMutex(); }
    }
}
