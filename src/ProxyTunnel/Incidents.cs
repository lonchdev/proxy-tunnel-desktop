using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProxyTunnelPrototype;

public sealed class Incident
{
    public string Id { get; set; }="";
    public string Host { get; set; }="";
    public int Port { get; set; }
    public DateTimeOffset At { get; set; }
    public string Reason { get; set; }="";
    public string Context { get; set; }="";
    public string Version { get; set; }="";
    public string ServerStatus { get; set; }="Ожидание конца интервала";
    public DateTimeOffset NextAttempt { get; set; }
    public int Attempts { get; set; }
    public bool ServerReceived { get; set; }
    public bool BeforeReady { get; set; }
    public string CaptureWarning { get; set; }="";
    public DateTimeOffset From=>At.AddMinutes(-5);
    public DateTimeOffset Until=>At.AddMinutes(5);
}

public sealed class IncidentStore
{
    readonly object sync=new();
    readonly string root;
    readonly List<Incident> items=[];
    long lastPrune;
    static readonly string[] Files=["incident.json","pc-before.log","pc-after.log","vps.log"];
    public IncidentStore(string? path=null)
    {
        root=path??Path.Combine(Settings.DataDir,"incidents"); Directory.CreateDirectory(root);
        foreach(var folder in Directory.EnumerateDirectories(root))
        {
            if(!ValidId(Path.GetFileName(folder))||(File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0) continue;
            try { var item=JsonSerializer.Deserialize<Incident>(File.ReadAllText(Path.Combine(folder,"incident.json"))); if(item!=null&&ValidId(item.Id)&&Path.GetFileName(folder)==item.Id) items.Add(item); } catch(Exception ex) when(ex is IOException or JsonException or UnauthorizedAccessException) { }
        }
        Prune();
    }
    static bool ValidId(string id)=>Regex.IsMatch(id,@"^\d{8}-\d{6}-[a-f0-9]{8}$");
    string Folder(Incident item)
    {
        if(!ValidId(item.Id)) throw new IOException("Некорректный номер отчёта.");
        return Path.Combine(root,item.Id);
    }
    void Save(Incident item)=>AtomicFile.Write(Path.Combine(Folder(item),"incident.json"),JsonSerializer.Serialize(item));
    public Incident? Latest { get { lock(sync) return items.OrderByDescending(i=>i.At).FirstOrDefault(); } }
    public Incident Begin(string host,int port,string reason,string context,DateTimeOffset at)=>Begin(host,port,reason,context,at,out _);
    internal Incident Begin(string host,int port,string reason,string context,DateTimeOffset at,out bool created)
    {
        lock(sync)
        {
            created=false;
            var existing=items.LastOrDefault(i=>i.Host==host&&i.Port==port&&at>=i.At&&at<=i.Until);
            if(existing!=null) return existing;
            var item=new Incident{Id=at.UtcDateTime.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N")[..8],Host=host,Port=port,At=at,Reason=LogPrivacy.Clean(reason),Context=LogPrivacy.Clean(context),Version=typeof(Incident).Assembly.GetName().Version?.ToString()??"",NextAttempt=at.AddMinutes(5)};
            Directory.CreateDirectory(Folder(item)); Save(item); items.Add(item); created=true; Prune(); return item;
        }
    }
    public void Before(Incident item,string text)
    {
        lock(sync) try { if(!items.Contains(item)) return; AtomicFile.Write(Path.Combine(Folder(item),"pc-before.log"),$"ПК · до сбоя {item.Id}\nИнтервал: {item.From:O} — {item.At:O}\nСохранившиеся записи; полнота зависит от ротации журнала.\n\n"+LogPrivacy.Clean(text)); item.BeforeReady=true; Save(item); Prune(); }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { item.CaptureWarning="Не сохранена часть до сбоя: "+ex.Message; TrySave(item); }
    }
    public void Append(LogRecord record)
    {
        lock(sync)
        {
        foreach(var item in items.Where(i=>new DateTimeOffset(record.Time)>=i.At&&new DateTimeOffset(record.Time)<=i.Until))
        {
            try
            {
                var file=Path.Combine(Folder(item),"pc-after.log");
                if(File.Exists(file)&&new FileInfo(file).Length>1024*1024) { if(item.CaptureWarning!="Хвост логов ПК ограничен 1 МБ.") { item.CaptureWarning="Хвост логов ПК ограничен 1 МБ."; TrySave(item); } continue; }
                File.AppendAllText(file,$"{record.Time:yyyy-MM-dd HH:mm:ss.fff zzz}  [PC] {LogPrivacy.Clean(record.Message)}\n");
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { item.CaptureWarning="Не записана часть после сбоя: "+ex.Message; TrySave(item); }
        }
        if(Environment.TickCount64-lastPrune>10000) { lastPrune=Environment.TickCount64; try { Prune(); } catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { } }
        }
    }
    void TrySave(Incident item) { try { Save(item); } catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { } }
    public Incident? Due(string host,int port,DateTimeOffset now)
    {
        lock(sync) return items.Where(i=>i.Host==host&&i.Port==port&&!i.ServerReceived&&i.Until<=now&&i.NextAttempt<=now).OrderByDescending(i=>i.At).FirstOrDefault();
    }
    public void Received(Incident item,VpsLogReport report)
    {
        lock(sync)
        {
            if(!items.Contains(item)) return;
            AtomicFile.Write(Path.Combine(Folder(item),"vps.log"),LogPrivacy.Clean(report.Text));
            item.ServerReceived=!report.ObserverError; item.ServerStatus=report.ObserverError?"Журнал службы получен; история наблюдателя ожидает повторной загрузки":report.Truncated?"Получен неполный серверный отчёт (ограничение размера)":"Серверный отчёт получен";
            if(report.ObserverError) { item.Attempts++; item.NextAttempt=DateTimeOffset.UtcNow.AddMinutes(Math.Min(10,item.Attempts)); }
            Save(item); Prune();
        }
    }
    public void Failed(Incident item,string reason,DateTimeOffset now)
    {
        lock(sync) { if(!items.Contains(item)) return; item.Attempts++; item.ServerStatus="Ожидает повторного получения: "+LogPrivacy.Clean(reason); item.NextAttempt=now.AddMinutes(Math.Min(10,item.Attempts)); TrySave(item); }
    }
    public void ExportLatest(string destination)=>Export(Latest?.Id??throw new InvalidOperationException("Зафиксированных сбоев пока нет."),destination);
    public void Export(string id,string destination)
    {
        Incident item;
        Dictionary<string,byte[]> snapshot;
        string noteText;
        lock(sync)
        {
            item=items.FirstOrDefault(i=>i.Id==id)??throw new InvalidOperationException("Этот отчёт уже удалён ротацией хранилища.");
            noteText=$"Сбой {item.Id}\nВремя: {item.At:O}\nПричина: {item.Reason}\n{item.ServerStatus}\n{item.CaptureWarning}\n"+(!item.BeforeReady?"Часть до сбоя ещё не сохранена.\n":"")+"Окно: 5 минут до и после события. Если приложение было закрыто или сеть недоступна, часть данных может отсутствовать.\n";
            snapshot=Files.Where(name=>File.Exists(Path.Combine(Folder(item),name))).ToDictionary(name=>name,name=>File.ReadAllBytes(Path.Combine(Folder(item),name)));
        }
        // Compression or a slow destination must not block transport log writers.
        using var file=new FileStream(destination,FileMode.Create,FileAccess.Write,FileShare.None); using var zip=new ZipArchive(file,ZipArchiveMode.Create);
        var note=zip.CreateEntry("Отчёт.txt"); using(var writer=new StreamWriter(note.Open())) writer.Write(noteText);
        foreach(var pair in snapshot) { using var stream=zip.CreateEntry(pair.Key).Open(); stream.Write(pair.Value); }
    }
    void Prune()
    {
        long Size()=>items.Sum(i=>Files.Sum(name=> { var path=Path.Combine(Folder(i),name); return File.Exists(path)?new FileInfo(path).Length:0; }));
        while(items.Count>1&&(items.Count>20||Size()>50L*1024*1024))
        {
            var old=items.OrderBy(i=>i.At).First(); var dir=Folder(old);
            foreach(var name in Files) File.Delete(Path.Combine(dir,name));
            if(!Directory.EnumerateFileSystemEntries(dir).Any()) Directory.Delete(dir); items.Remove(old);
        }
    }
}
