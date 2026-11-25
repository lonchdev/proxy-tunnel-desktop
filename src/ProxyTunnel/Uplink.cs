using System.IO;

namespace ProxyTunnelPrototype;

internal sealed record Uplink(string Id,string Name,int Index,string Addresses,string Gateways)
{
    public string Key=>$"{Id}|{Name}|{Index}|{Addresses}|{Gateways}";
}
internal sealed class UplinkStability
{
    string? candidate;
    TimeSpan since;
    bool initialized;
    public static readonly TimeSpan SettleTime=TimeSpan.FromSeconds(3);
    public bool Ready(Uplink? link,TimeSpan now)
    {
        if(!initialized||candidate!=link?.Key) { initialized=true; candidate=link?.Key; since=now; }
        return link!=null&&now-since>=SettleTime;
    }
    public void Reset() { initialized=false; candidate=null; }
    public static bool RequiresRebind(Uplink? bound,Uplink? current,bool invalidated)=>invalidated||bound!=null&&bound.Key!=current?.Key;
}
internal sealed class UplinkUnavailableException(string message):IOException(message);
