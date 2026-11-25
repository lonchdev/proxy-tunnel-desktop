using System.Net.Sockets;

namespace ProxyTunnelPrototype;

internal sealed class TrafficHealth
{
    readonly object sync=new();
    readonly Queue<TimeSpan> failures=new();
    public void Failure(TimeSpan now) { lock(sync) { Trim(now); failures.Enqueue(now); } }
    public int Recent(TimeSpan now) { lock(sync) { Trim(now); return failures.Count; } }
    void Trim(TimeSpan now) { while(failures.Count>0&&now-failures.Peek()>TimeSpan.FromSeconds(90)) failures.Dequeue(); }
    public static bool IsVpsFailure(string text,string host,int port)=>text.Contains("dial tcp "+host+":"+port+":",StringComparison.Ordinal)&&
        (text.Contains("timeout",StringComparison.OrdinalIgnoreCase)||text.Contains("unreachable",StringComparison.OrdinalIgnoreCase)||text.Contains("no route",StringComparison.OrdinalIgnoreCase)||text.Contains("connectex",StringComparison.OrdinalIgnoreCase)||text.Contains("invalid argument",StringComparison.OrdinalIgnoreCase));
    public static bool IsExpectedClose(Exception error)
    {
        for(Exception? item=error;item!=null;item=item.InnerException)
            if(item is SocketException socket&&socket.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.OperationAborted) return true;
        return false;
    }
}
