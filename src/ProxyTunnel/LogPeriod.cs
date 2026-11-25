namespace ProxyTunnelPrototype;

public enum LogPeriod { Hour, FiveHours, Day, Week, Month, All }
public static class LogPeriods
{
    public static DateTime Start(LogPeriod period,DateTime now)=>period switch
    {
        LogPeriod.Hour=>now.AddHours(-1),
        LogPeriod.FiveHours=>now.AddHours(-5),
        LogPeriod.Day=>now.Date.AddMinutes(1),
        LogPeriod.Week=>now.AddDays(-7),
        LogPeriod.Month=>now.AddMonths(-1),
        _=>DateTime.MinValue
    };
    public static string Label(LogPeriod period)=>period switch
    {
        LogPeriod.Hour=>"1h",LogPeriod.FiveHours=>"5h",LogPeriod.Day=>"1d",
        LogPeriod.Week=>"7d",LogPeriod.Month=>"1m",_=>"∞"
    };
}
