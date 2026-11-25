using System.IO;
using System.Text.Json;

namespace ProxyTunnelPrototype;

static class LogPeriodTests
{
    public static int Run()
    {
        var lines=new List<string>();
        void Check(bool ok,string text) { if(!ok) throw new Exception(text); lines.Add("PASS: "+text); }
        try
        {
            var now=new DateTime(2026,11,25,13,30,0,DateTimeKind.Local);
            var root=Path.Combine(Settings.DataDir,"periods-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            var records=new List<LogRecord>();
            void Add(DateTime time,string message,string? key=null)=>records.Add(new(records.Count+1,time,LogSeverity.Info,message,key??message));
            Add(now.AddDays(-40),"old"); Add(now.AddMonths(-1).AddSeconds(-1),"before-month"); Add(now.AddMonths(-1),"month-start");
            Add(now.AddDays(-7).AddSeconds(-1),"before-week"); Add(now.AddDays(-7),"week-start");
            Add(now.Date.AddSeconds(59),"before-day"); Add(now.Date.AddMinutes(1),"day-start");
            Add(now.AddHours(-5).AddSeconds(-1),"before-five"); Add(now.AddHours(-5),"five-start");
            Add(now.AddHours(-1).AddSeconds(-1),"repeat","repeat"); Add(now.AddHours(-1),"repeat","repeat"); Add(now.AddHours(-1).AddSeconds(1),"repeat","repeat");
            Add(now,"current Authorization: Bearer private-test-token"); Add(now.AddSeconds(1),"future");
            // Put the older part in the rotated file and more than 1000 rows
            // after it: copying must use disk history rather than the UI cap.
            File.WriteAllLines(Path.Combine(root,"journal.previous.jsonl"),records.Take(5).Select(r=>JsonSerializer.Serialize(r)));
            var current=records.Skip(5).ToList();
            for(int i=0;i<1100;i++) current.Add(new(100+i,now.AddMinutes(-10).AddMilliseconds(i),LogSeverity.Info,"row-"+i,"row-"+i));
            current.Add(new(2000,now.AddSeconds(-2),LogSeverity.Critical,"urgent","urgent"));
            File.WriteAllLines(Path.Combine(root,"journal.jsonl"),current.Select(r=>JsonSerializer.Serialize(r)));
            var legacy=Path.Combine(root,"activity.log");
            File.WriteAllLines(legacy,new[]{"23:59:59 legacy-yesterday","00:00:30 legacy-before-day","00:01:00 legacy-day-start"}); File.SetLastWriteTime(legacy,now);
            var journal=new Journal(root,()=>now);
            var hour=journal.CopyText(LogPeriod.Hour,now);
            Check(hour.Contains("[повторов: 2;")&&!hour.Contains("[повторов: 3;")&&!hour.Contains("before-five"),"1h filters individual occurrences before grouping, including the exact start boundary");
            var five=journal.CopyText(LogPeriod.FiveHours,now);
            Check(five.Contains("five-start")&&!five.Contains("before-five"),"5h uses a rolling five-hour interval");
            var day=journal.CopyText(LogPeriod.Day,now);
            Check(day.Contains("day-start")&&!day.Contains("before-day"),"1d starts at 00:01 of the copying date");
            var week=journal.CopyText(LogPeriod.Week,now);
            Check(week.Contains("week-start")&&!week.Contains("before-week"),"7d includes the boundary in the rotated journal");
            var month=journal.CopyText(LogPeriod.Month,now);
            Check(month.Contains("month-start")&&!month.Contains("before-month"),"1m uses a calendar month back from the copying time");
            var all=journal.CopyText(LogPeriod.All,now);
            Check(!all.Contains("old")&&all.Contains("row-0")&&all.Contains("row-1099")&&journal.Snapshot().Count>1000,"Infinity includes retained disk history beyond the 1000 UI rows");
            Check(!hour.Contains("future")&&all.Contains("future")&&!all.Contains("private-test-token"),"Bounded periods exclude future events; infinity preserves all dates; secrets stay redacted");
            Check(LogPeriods.Start(LogPeriod.Month,new DateTime(2024,3,31,12,0,0))==new DateTime(2024,2,29,12,0,0),"Calendar month handles leap years and month ends");
            Check(journal.CopyText(LogPeriod.Day,now.Date.AddSeconds(30))==""&&new Journal(Path.Combine(root,"empty")).CopyText(LogPeriod.Day,now)=="","Before 00:01 and empty periods return no text");
            Check(journal.UnreadCount==1,"Copying does not acknowledge unread urgent problems");
            Check(all.Contains("legacy-yesterday")&&day.Contains("legacy-day-start")&&!day.Contains("legacy-before-day")&&!day.Contains("legacy-yesterday"),"Legacy journals preserve history and infer midnight crossings before period filtering");
            var retentionRoot=Path.Combine(root,"retention"); Directory.CreateDirectory(retentionRoot);
            var clockNow=now;
            var retained=new[]{new LogRecord(1,now.AddMonths(-1).AddSeconds(-1),LogSeverity.Info,"expired","expired"),new LogRecord(2,now.AddMonths(-1),LogSeverity.Info,"boundary","boundary"),new LogRecord(3,now.AddHours(-25),LogSeverity.Info,"yesterday","yesterday"),new LogRecord(4,now.AddHours(-1),LogSeverity.Info,"fresh","fresh")};
            File.WriteAllLines(Path.Combine(retentionRoot,"journal.jsonl"),retained.Select(r=>JsonSerializer.Serialize(r)));
            var retention=new Journal(retentionRoot,()=>clockNow);
            Check(!retention.CopyText(LogPeriod.All).Contains("expired")&&retention.CopyText(LogPeriod.All).Contains("boundary"),"Month retention removes expired records and preserves the exact calendar boundary");
            Check(retention.Snapshot().Count==1&&retention.Snapshot()[0].Message=="fresh","Screen shows only the last rolling 24 hours while older records remain exportable");
            clockNow=now.AddMonths(1).AddHours(2); retention.Add("new day");
            Check(!retention.CopyText(LogPeriod.All).Contains("fresh")&&!File.Exists(Path.Combine(retentionRoot,"journal.jsonl")),"Running application cleans expired history without a restart");
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"log-period-test.txt"),lines); }
    }
}
