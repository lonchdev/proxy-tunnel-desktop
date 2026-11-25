using System.Reflection;

namespace ProxyTunnelPrototype;

internal static class ReportBundle
{
    public static string Compose(LogPeriod period,DateTimeOffset at,string pc,VpsLogReport? server,string? error)
    {
        var version=Assembly.GetExecutingAssembly().GetName().Version;
        var status=server==null?"серверная часть не получена":server.Truncated||server.ObserverError?"серверная часть неполная":server.ObserverAvailable?"журнал службы и история наблюдателя получены":"журнал службы получен; без истории наблюдателя";
        return $"Proxy Tunnel {version} · общий отчёт\nВремя ПК: {at:yyyy-MM-dd HH:mm:ss zzz}; период: {LogPeriods.Label(period)}.\nVPS: {status}.\n\n=== ПК ===\n"+
            (string.IsNullOrWhiteSpace(pc)?"За выбранный период записей ПК нет.":LogPrivacy.Clean(pc))+"\n\n=== VPS ===\n"+
            (server!=null?LogPrivacy.Clean(server.Text):"СЕРВЕРНЫЕ ЛОГИ НЕ ПОЛУЧЕНЫ.\nПричина: "+LogPrivacy.Clean(error??"неизвестна")+"\nЭто не доказывает неисправность VPS: причиной может быть недоступность канала, SSH или ключа.");
    }
}
