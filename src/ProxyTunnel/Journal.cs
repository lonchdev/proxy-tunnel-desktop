using System.IO;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProxyTunnelPrototype;

public enum LogSeverity { Info, Warning, Critical }
public sealed record LogRecord(long Sequence,DateTime Time,LogSeverity Severity,string Message,string Key);
public sealed class LogRow
{
    public DateTime First { get; set; }
    public DateTime Last { get; set; }
    public LogSeverity Severity { get; set; }
    public string Message { get; set; }="";
    public string Key { get; set; }="";
    public int Repeats { get; set; }
    public long Sequence { get; set; }
    public string Display=>$"{Last:yyyy-MM-dd HH:mm:ss}  {Message}"+(Repeats>1?$"  [повторов: {Repeats}; с {First:HH:mm:ss}]":"");
}

public static class AtomicFile
{
    public static void Write(string path,string text,bool backup=false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp=path+".tmp-"+Guid.NewGuid().ToString("N");
        try { File.WriteAllText(temp,text); if(backup&&File.Exists(path)) File.Copy(path,path+".bak",true); File.Move(temp,path,true); }
        finally { if(File.Exists(temp)) File.Delete(temp); }
    }
}

public static class LogPrivacy
{
    public static string Clean(string text)
    {
        text=Regex.Replace(text,@"\x1B\[[0-?]*[ -/]*[@-~]","");
        text=Regex.Replace(text,@"(?im)\b(Authorization|Proxy-Authorization)\s*:\s*[^\r\n]+","$1: [скрыто]");
        text=Regex.Replace(text,@"(?i)(https?|socks[45]?)://[^/\s@]+@","$1://[скрыто]@");
        text=Regex.Replace(text,"(?i)([?&](?:access_token|refresh_token|id_token|token|key|api_key|code|client_secret|password|secret)=)[^&\\s\"'#]+","$1[скрыто]");
        text=Regex.Replace(text,"(?i)(\"(?:password|client_secret|access_token|refresh_token|id_token|api_key|secret)\"\\s*:\\s*)\"[^\"]*\"","$1\"[скрыто]\"");
        return text;
    }
}

public sealed class Journal
{
    readonly object sync=new();
    readonly List<LogRow> rows=[];
    readonly HashSet<string> unread=[];
    readonly Queue<LogRecord> recentRecords=new();
    readonly string directory;
    long sequence,seen;
    DateTime lastCleanup;
    readonly Func<DateTime> clock;
    bool visible;
    public event Action? Changed;
    public event Action<LogRecord>? Recorded;
    string Current=>Path.Combine(directory,"journal-"+clock().ToString("yyyy-MM-dd")+".jsonl");
    IEnumerable<string> JournalFiles()=>Directory.EnumerateFiles(directory,"journal-????-??-??.jsonl").Concat(new[]{Previous,Path.Combine(directory,"journal.jsonl"),Path.Combine(directory,"journal-legacy.jsonl")}).Where(File.Exists).Distinct().OrderBy(p=>p);
    void Cleanup()
    {
        var now=clock(); if(lastCleanup!=default&&now-lastCleanup<TimeSpan.FromHours(1)) return;
        var cutoff=now.AddMonths(-1);
        while(recentRecords.Count>0&&recentRecords.Peek().Time<cutoff) recentRecords.Dequeue();
        foreach(var file in JournalFiles().ToArray())
        {
            var kept=new List<string>(); var removed=false;
            foreach(var line in File.ReadLines(file)) try { var r=JsonSerializer.Deserialize<LogRecord>(line); if(r!=null&&r.Time>=cutoff) kept.Add(line); else removed=true; } catch(JsonException) { removed=true; }
            if(kept.Count==0) File.Delete(file); else if(removed) AtomicFile.Write(file,string.Join(Environment.NewLine,kept)+Environment.NewLine);
        }
        var legacy=Path.Combine(directory,"activity.log");
        if(File.Exists(legacy))
        {
            var kept=LegacyRecords().Where(r=>r.Time>=cutoff).OrderBy(r=>r.Time).ToArray();
            var migrated=Path.Combine(directory,"journal-legacy.jsonl");
            if(kept.Length>0) AtomicFile.Write(migrated,string.Join(Environment.NewLine,kept.Select(r=>JsonSerializer.Serialize(r)))+Environment.NewLine);
            File.Delete(legacy);
        }
        var migration=Path.Combine(directory,"journal-legacy.jsonl");
        if(File.Exists(migration)&&File.GetLastWriteTime(migration)<cutoff) File.Delete(migration);
        lastCleanup=now;
    }
    public void Maintain() { lock(sync) Cleanup(); }
    string Previous=>Path.Combine(directory,"journal.previous.jsonl");
    string SeenFile=>Path.Combine(directory,"journal-seen.txt");
    public Journal(string? directory=null,Func<DateTime>? clock=null)
    {
        this.clock=clock??(()=>DateTime.Now); this.directory=directory??Settings.DataDir; Directory.CreateDirectory(this.directory);
        if(File.Exists(SeenFile)) long.TryParse(File.ReadAllText(SeenFile),out seen);
        sequence=seen;
        Cleanup();
        var records=new List<LogRecord>();
        foreach(var file in JournalFiles())
            foreach(var line in File.ReadLines(file))
                try { var record=JsonSerializer.Deserialize<LogRecord>(line); if(record!=null) records.Add(record); } catch(JsonException) { }
        foreach(var record in records.OrderBy(r=>r.Time).ThenBy(r=>r.Sequence)) Merge(record);
        var loaded=records.Count>0;
        var legacy=Path.Combine(this.directory,"activity.log");
        if(!loaded&&File.Exists(legacy)) foreach(var line in File.ReadLines(legacy).TakeLast(500)) Add(line,persist:false);
    }
    public int UnreadCount { get { lock(sync) return unread.Count; } }
    public IReadOnlyList<LogRow> Snapshot()
    {
        lock(sync) return rows.Where(r=>r.Last>=clock().AddHours(-24)).OrderBy(r=>r.Last).Select(r=>new LogRow{First=r.First,Last=r.Last,Severity=r.Severity,Message=r.Message,Key=r.Key,Repeats=r.Repeats,Sequence=r.Sequence}).ToArray();
    }
    public static LogSeverity Classify(string text)
    {
        if(text.Contains("empty result",StringComparison.OrdinalIgnoreCase)&&(text.Contains("ipv6.msftconnecttest.com",StringComparison.OrdinalIgnoreCase)||text.Contains("ipv6.msftncsi.com",StringComparison.OrdinalIgnoreCase))) return LogSeverity.Info;
        if(text.Contains(":7680")&&text.Contains("timeout",StringComparison.OrdinalIgnoreCase)) return LogSeverity.Info;
        if(text.StartsWith("[CRITICAL]",StringComparison.Ordinal)||text.Contains("FATAL",StringComparison.Ordinal)||text.Contains("Ключ SSH-сервера изменился")||text.Contains("Не удалось восстановить прокси")||text.Contains("Прямой обход правил не разрешён")) return LogSeverity.Critical;
        if(text.Contains("ERROR",StringComparison.Ordinal)||text.StartsWith("[WARN]",StringComparison.Ordinal)||text.Contains("тайм-аут")||text.Contains("Ошибка:")) return LogSeverity.Warning;
        return LogSeverity.Info;
    }
    public string Add(string text,LogSeverity? severity=null,string? key=null,bool persist=true)
    {
        text=LogPrivacy.Clean(text); var level=severity??Classify(text);
        var stable=key??StableKey(text);
        var time=clock();
        LogRecord record;
        lock(sync)
        {
            if(level==LogSeverity.Warning&&text.Contains("ERROR")&&rows.Where(r=>r.Key==stable&&time-r.Last<TimeSpan.FromMinutes(5)).Sum(r=>r.Repeats)>=4) level=LogSeverity.Critical;
            sequence=Math.Max(sequence+1,DateTime.UtcNow.Ticks);
            record=new LogRecord(sequence,time,level,text,stable); Merge(record);
            if(persist) { recentRecords.Enqueue(record); while(recentRecords.Count>1000) recentRecords.Dequeue(); }
            if(persist)
            {
                try
                {
                    Cleanup();
                    File.AppendAllText(Current,JsonSerializer.Serialize(record)+Environment.NewLine);
                }
                catch { /* Keep the on-screen report available even if disk writing fails. */ }
            }
            if(visible) { seen=sequence; unread.Clear(); if(level==LogSeverity.Critical) SaveSeen(); }
        }
        Recorded?.Invoke(record); Changed?.Invoke(); return $"{time:HH:mm:ss}  {text}";
    }
    static string StableKey(string text)
    {
        if(text.Contains(":7680")&&text.Contains("timeout",StringComparison.OrdinalIgnoreCase)) return "local-update-peer-timeout";
        var key=Regex.Replace(text,@"\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d|\b\d\d:\d\d:\d\d\b","");
        key=Regex.Replace(key,@"\[[0-9]+(?:\s+[^\]]+)?\]|#[0-9]+","");
        return Regex.Replace(key,@"\s+"," ").Trim();
    }
    void Merge(LogRecord record)
    {
        sequence=Math.Max(sequence,record.Sequence);
        var row=rows.LastOrDefault(r=>r.Key==record.Key&&r.Severity==record.Severity&&record.Time-r.Last<TimeSpan.FromMinutes(5));
        if(row==null) { row=new LogRow{First=record.Time,Key=record.Key,Severity=record.Severity}; rows.Add(row); }
        row.Last=record.Time; row.Message=record.Message; row.Repeats++; row.Sequence=record.Sequence;
        if(record.Severity==LogSeverity.Critical&&record.Sequence>seen&&!visible) unread.Add(record.Key);
        rows.RemoveAll(r=>r.Last<clock().AddHours(-24));
        unread.RemoveWhere(key=>!rows.Any(r=>r.Key==key));
    }
    public void SetVisible(bool value)
    {
        lock(sync) { visible=value; if(value) { seen=sequence; unread.Clear(); SaveSeen(); } }
        Changed?.Invoke();
    }
    void SaveSeen() { try { AtomicFile.Write(SeenFile,seen.ToString()); } catch { } }
    public string ExportText()=>string.Join(Environment.NewLine,Snapshot().Select(r=>r.Display));
    public string CopyText(LogPeriod period,DateTime? at=null)
    {
        var now=at??DateTime.Now; var start=LogPeriods.Start(period,now);
        return FilteredText(period==LogPeriod.All?null:start,period==LogPeriod.All?null:now);
    }
    public string RangeText(DateTime from,DateTime until)=>FilteredText(from,until);
    string FilteredText(DateTime? start,DateTime? until)
    {
        lock(sync)
        {
            Cleanup();
            var records=new Dictionary<long,LogRecord>();
            foreach(var record in LegacyRecords()) records[record.Sequence]=record;
            // Read saved events before grouping: a repeated row can straddle a
            // period boundary and must not include occurrences outside it.
            foreach(var file in JournalFiles())
                if(File.Exists(file)) foreach(var line in File.ReadLines(file))
                    try { var record=JsonSerializer.Deserialize<LogRecord>(line); if(record!=null) records[record.Sequence]=record; } catch(JsonException) { }
            foreach(var record in recentRecords) records[record.Sequence]=record;
            if(records.Count==0) return start==null?ExportText():"";
            var grouped=new List<LogRow>();
            var latest=new Dictionary<(string,LogSeverity),LogRow>();
            foreach(var record in records.Values.Where(r=>(start==null||r.Time>=start)&&(until==null||r.Time<=until)).OrderBy(r=>r.Time).ThenBy(r=>r.Sequence))
            {
                var key=(record.Key,record.Severity);
                if(!latest.TryGetValue(key,out var row)||record.Time-row.Last>=TimeSpan.FromMinutes(5))
                { row=new LogRow{First=record.Time,Key=record.Key,Severity=record.Severity}; latest[key]=row; grouped.Add(row); }
                row.Last=record.Time; row.Sequence=record.Sequence; row.Message=LogPrivacy.Clean(record.Message); row.Repeats++;
            }
            return string.Join(Environment.NewLine,grouped.OrderBy(r=>r.Last).ThenBy(r=>r.Sequence).Select(r=>r.Display));
        }
    }
    IEnumerable<LogRecord> LegacyRecords()
    {
        var path=Path.Combine(directory,"activity.log");
        if(!File.Exists(path)) yield break;
        var entries=new List<(TimeSpan Time,string Body)>();
        foreach(var line in File.ReadLines(path))
        {
            var match=Regex.Match(line,@"^(\d\d:\d\d:\d\d)\s+(.*)$");
            if(match.Success&&TimeSpan.TryParseExact(match.Groups[1].Value,@"hh\:mm\:ss",CultureInfo.InvariantCulture,out var time)) entries.Add((time,match.Groups[2].Value));
            else if(entries.Count>0) { var last=entries[^1]; entries[^1]=(last.Time,last.Body+Environment.NewLine+line); }
        }
        // Older journals had only HH:mm:ss. Use embedded engine dates when
        // available; otherwise infer midnight crossings from file modification.
        var date=File.GetLastWriteTime(path).Date; var previous=TimeSpan.FromDays(1);
        for(int i=entries.Count-1;i>=0;i--)
        {
            var entry=entries[i];
            if(entry.Time>previous) date=date.AddDays(-1);
            var stamp=date+entry.Time;
            var embedded=Regex.Match(entry.Body,@"\b(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\b");
            if(embedded.Success&&DateTime.TryParseExact(embedded.Groups[1].Value,"yyyy-MM-dd HH:mm:ss",CultureInfo.InvariantCulture,DateTimeStyles.AssumeLocal,out var exact)) { stamp=exact; date=stamp.Date; }
            previous=entry.Time;
            var body=LogPrivacy.Clean(entry.Body);
            yield return new(i-entries.Count,stamp,Classify(body),body,StableKey(body));
        }
    }
}
