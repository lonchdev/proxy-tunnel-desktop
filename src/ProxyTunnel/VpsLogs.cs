using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ProxyTunnelPrototype;

public sealed record VpsLogReport(string Text,int Entries,bool Truncated,DateTimeOffset RetrievedAt,bool ObserverAvailable=false,bool ObserverError=false);
internal static class VpsLogs
{
    internal const int ByteLimit=1024*1024;
    internal static string Epoch(DateTimeOffset time)=>(time.ToUnixTimeMilliseconds()/1000m).ToString("0.000",CultureInfo.InvariantCulture);
    internal static string Query(LogPeriod period,DateTimeOffset at,TimeSpan clockOffset)
    {
        return Query(period==LogPeriod.All?null:new DateTimeOffset(LogPeriods.Start(period,at.LocalDateTime)),period==LogPeriod.All?null:at,clockOffset);
    }
    internal static string Query(DateTimeOffset? from,DateTimeOffset? until,TimeSpan clockOffset)
    {
        var window=(from.HasValue?" --since=@"+Epoch(from.Value.ToUniversalTime()+clockOffset):"")+(until.HasValue?" --until=@"+Epoch(until.Value.ToUniversalTime()+clockOffset):"");
        return $"bash -o pipefail -c 'journalctl --quiet --no-pager --utc --output=json --output-fields=MESSAGE,PRIORITY --reverse --unit=proxy-tunnel-prototype{window} | head -c {ByteLimit+1}'";
    }
    internal static string ObserverQuery(DateTimeOffset? from,DateTimeOffset? until,TimeSpan offset)
    {
        var range=(from.HasValue?" --from "+Epoch(from.Value.ToUniversalTime()+offset):"")+(until.HasValue?" --until "+Epoch(until.Value.ToUniversalTime()+offset):"");
        return $"if test -r /opt/proxy-tunnel-observer/observer.py; then /usr/bin/python3 /opt/proxy-tunnel-observer/observer.py --export{range} --bytes {ByteLimit}; else printf 'PT_OBSERVER_NOT_INSTALLED\\n'; fi";
    }
    internal static TimeSpan ClockOffset(string epoch,DateTimeOffset sent,DateTimeOffset received)
    {
        if(!decimal.TryParse(epoch.Trim(),NumberStyles.AllowDecimalPoint,CultureInfo.InvariantCulture,out var seconds)) throw new FormatException("VPS не вернул корректное время.");
        var server=DateTimeOffset.UnixEpoch.AddMilliseconds((double)(seconds*1000));
        return server-(sent+(received-sent)/2);
    }
    internal static VpsLogReport Parse(string output,string error,int exit,LogPeriod period,DateTimeOffset at,TimeSpan offset,TimeSpan clockRoundTrip,string path,string? windowLabel=null)
    {
        var truncated=Encoding.UTF8.GetByteCount(output)>ByteLimit;
        if(exit!=0&&!(truncated&&exit==141)) throw new InvalidOperationException($"Не удалось прочитать журнал VPS (код {exit}): "+LogPrivacy.Clean(error.Trim()));
        var records=new List<(long Time,string Text)>(); var skipped=0;
        foreach(var line in output.Split('\n',StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var json=JsonDocument.Parse(line); var root=json.RootElement;
                if(!root.TryGetProperty("__REALTIME_TIMESTAMP",out var time)||!long.TryParse(time.GetString(),out var micros)||!root.TryGetProperty("MESSAGE",out var message)) { skipped++; continue; }
                var stamp=DateTimeOffset.FromUnixTimeMilliseconds(micros/1000);
                var text=message.ValueKind==JsonValueKind.String?message.GetString()!:message.ValueKind==JsonValueKind.Array?Encoding.UTF8.GetString(message.EnumerateArray().Select(b=>b.GetByte()).ToArray()):"[неподдерживаемая запись журнала]";
                records.Add((micros,$"{stamp:yyyy-MM-dd HH:mm:ss.fff}Z  [VPS] {LogPrivacy.Clean(text)}"));
            }
            catch(Exception ex) when(ex is JsonException or ArgumentOutOfRangeException or InvalidOperationException or FormatException) { skipped++; }
        }
        var report=new StringBuilder();
        report.AppendLine("Журнал VPS · служба proxy-tunnel-prototype");
        report.AppendLine($"Запрошено с ПК: {at:yyyy-MM-dd HH:mm:ss zzz}; период: {windowLabel??LogPeriods.Label(period)}; путь: {path}.");
        report.AppendLine($"Время серверных записей: UTC. Оценка разницы часов VPS − ПК: {offset.TotalSeconds.ToString("+0.000;-0.000;0.000",CultureInfo.InvariantCulture)} с; время запроса часов: {clockRoundTrip.TotalMilliseconds:F0} мс. Интервал запроса скорректирован на эту разницу.");
        report.AppendLine("Ниже существующий журнал службы. Данные отдельного наблюдателя добавляются своим разделом, если он установлен.");
        if(truncated) report.AppendLine("ВНИМАНИЕ: журнал превышает 1 МБ. Получены последние доступные записи выбранного периода; для полного фрагмента выберите более короткий период.");
        if(skipped>0) report.AppendLine($"Неполных или неподдерживаемых записей пропущено: {skipped}.");
        report.AppendLine($"Получено событий: {records.Count}."); report.AppendLine();
        foreach(var record in records.OrderBy(r=>r.Time)) report.AppendLine(record.Text);
        if(records.Count==0) report.AppendLine(skipped>0?"Читаемых записей не получено; часть данных не удалось разобрать.":"В доступном серверном журнале за выбранный период записей нет.");
        return new(report.ToString(),records.Count,truncated||skipped>0,DateTimeOffset.Now);
    }
    internal static VpsLogReport AddObserver(VpsLogReport service,string output,string error,int exit,DateTimeOffset at,TimeSpan offset,TimeSpan rtt,string path,string? windowLabel=null)
    {
        if(output.StartsWith("PT_OBSERVER_NOT_INSTALLED",StringComparison.Ordinal)) return service with {Text=service.Text+"\n=== Наблюдатель VPS ===\nНе установлен. История нагрузки и памяти недоступна.\n"};
        if(exit!=0||!output.StartsWith("PT_OBSERVER_READY",StringComparison.Ordinal)) return service with {Text=service.Text+"\n=== Наблюдатель VPS ===\nНЕ ПОЛУЧЕН: "+LogPrivacy.Clean(error)+"\n",ObserverError=true};
        var truncated=output.Contains("PT_OBSERVER_TRUNCATED=1",StringComparison.Ordinal);
        var skipped=System.Text.RegularExpressions.Regex.Match(output,@"PT_OBSERVER_SKIPPED=([0-9]+)").Groups[1].Value;
        var missing=skipped.Length>0&&skipped!="0";
        var data=string.Join('\n',output.Split('\n').Where(l=>!l.StartsWith("PT_OBSERVER_",StringComparison.Ordinal)));
        var observer=Parse(data,"",0,LogPeriod.All,at,offset,rtt,path,windowLabel??"тот же интервал, что у журнала службы");
        return service with {Text=service.Text+"\n=== Наблюдатель VPS ===\n"+(truncated?"ВНИМАНИЕ: история наблюдателя ограничена по размеру.\n":"")+(missing?"Неполных записей наблюдателя пропущено: "+skipped+".\n":"")+observer.Text,Entries=service.Entries+observer.Entries,Truncated=service.Truncated||truncated||missing||observer.Truncated,ObserverAvailable=true};
    }
}
