using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyTunnelPrototype;

// Correct only the authority syntax, before passing the request to the existing
// mixed proxy. TLS payloads are copied unchanged and are never intercepted.
public sealed class ProxyFront : IDisposable
{
    readonly TcpListener listener;
    readonly int backendPort;
    readonly Action<string>? log;
    readonly Func<string,bool>? selectedProcess;
    readonly Func<IPEndPoint,int,string?> ownerResolver;
    readonly CancellationTokenSource stop=new();
    readonly System.Collections.Concurrent.ConcurrentDictionary<TcpClient,byte> clients=new();
    public ProxyFront(int? port=null,int? backendPort=null,Action<string>? log=null,Func<string,bool>? selectedProcess=null,Func<IPEndPoint,int,string?>? ownerResolver=null) { listener=new(IPAddress.Loopback,port??ConfigBuilder.PortBase+2); this.backendPort=backendPort??ConfigBuilder.PortBase+3; this.log=log; this.selectedProcess=selectedProcess; this.ownerResolver=ownerResolver??WindowsConnectionOwner.Find; }
    public void Start() { listener.Start(); _=Accept(); }
    internal int ListenPort=>((IPEndPoint)listener.LocalEndpoint).Port;
    async Task Accept()
    {
        try { while(!stop.IsCancellationRequested) { var client=await listener.AcceptTcpClientAsync(stop.Token); clients.TryAdd(client,0); _=Forward(client); } }
        catch(OperationCanceledException) { } catch(SocketException) when(stop.IsCancellationRequested) { }
    }
    async Task Forward(TcpClient client)
    {
        using(client)
        using(var backend=new TcpClient())
        {
            var readingClient=true;
            try
            {
                client.NoDelay=true; backend.NoDelay=true;
                var owner=selectedProcess!=null?ownerResolver((IPEndPoint)client.Client.RemoteEndPoint!,((IPEndPoint)listener.LocalEndpoint).Port):null;
                if(selectedProcess!=null&&owner==null) throw new IOException("Не определён процесс запроса. Прямой обход правил не разрешён; запустите приложение от администратора.");
                var selectedBackend=owner!=null&&selectedProcess?.Invoke(owner)==true?ConfigBuilder.PortBase:backendPort;
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(12));
                var input=client.GetStream(); using var header=new MemoryStream(); var one=new byte[1]; var tail=0;
                while(header.Length<32768)
                {
                    var count=await input.ReadAsync(one,timeout.Token); if(count==0) return;
                    header.WriteByte(one[0]); tail=(tail<<8)|one[0]; if(tail==0x0d0a0d0a) break;
                    if(header.Length==1&&one[0] is 4 or 5)
                    {
                        readingClient=false;
                        await backend.ConnectAsync(IPAddress.Loopback,selectedBackend,timeout.Token);
                        var socksOutput=backend.GetStream(); await socksOutput.WriteAsync(one,timeout.Token);
                        await Relay(client,backend); return;
                    }
                }
                if(tail!=0x0d0a0d0a) throw new IOException("Заголовок HTTP-прокси слишком большой.");
                var original=Encoding.Latin1.GetString(header.ToArray()); var normalized=Normalize(original);
                if(normalized!=original) log?.Invoke("Совместимость IPv6: исправлен формат адреса в запросе к прокси.");
                var requestLine=normalized.Split("\r\n",2)[0].Split(' ',3);
                if(requestLine.Length==3&&requestLine[0].Equals("CONNECT",StringComparison.OrdinalIgnoreCase)&&Uri.TryCreate("http://"+requestLine[1],UriKind.Absolute,out var destination))
                    if(destination.Host.EndsWith("googleapis.com",StringComparison.OrdinalIgnoreCase)||destination.Host.EndsWith("antigravity.google",StringComparison.OrdinalIgnoreCase)||destination.Host.Equals("accounts.google.com",StringComparison.OrdinalIgnoreCase))
                        log?.Invoke("Запрос к Google через локальный прокси: "+destination.Host+":"+destination.Port+"; процесс: "+(owner??WindowsConnectionOwner.Find((IPEndPoint)client.Client.RemoteEndPoint!,((IPEndPoint)listener.LocalEndpoint).Port)??"не определён")+" (без токенов и содержимого).");
                readingClient=false;
                await backend.ConnectAsync(IPAddress.Loopback,selectedBackend,timeout.Token);
                var output=backend.GetStream(); await output.WriteAsync(Encoding.Latin1.GetBytes(normalized),timeout.Token);
                await Relay(client,backend);
            }
            catch(Exception ex) when(ex is IOException or SocketException or OperationCanceledException)
            {
                if(!stop.IsCancellationRequested&&ex is not OperationCanceledException)
                    log?.Invoke(ex is RelayFailure failure&&failure.ClientClosed||readingClient&&TrafficHealth.IsExpectedClose(ex)?"Приложение закрыло соединение с локальным прокси.":"[WARN] HTTP-прокси: "+ex.Message);
            }
            catch(ObjectDisposedException) when(stop.IsCancellationRequested) { }
            finally { clients.TryRemove(client,out _); }
        }
    }
    async Task Relay(TcpClient client,TcpClient backend)
    {
        using var relay=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
        var clientStream=client.GetStream(); var backendStream=backend.GetStream();
        async Task Pump(TcpClient source,TcpClient destination,bool sourceIsClient)
        {
            try
            {
                var buffer=new byte[65536];
                var input=sourceIsClient?clientStream:backendStream;
                var output=sourceIsClient?backendStream:clientStream;
                while(true)
                {
                    int count;
                    try { count=await input.ReadAsync(buffer,relay.Token); }
                    catch(Exception ex) when(ex is IOException or SocketException) { throw new RelayFailure(sourceIsClient&&TrafficHealth.IsExpectedClose(ex),sourceIsClient?"Чтение от приложения":"Чтение от сетевого процесса",ex); }
                    if(count==0) break;
                    try { await output.WriteAsync(buffer.AsMemory(0,count),relay.Token); }
                    catch(Exception ex) when(ex is IOException or SocketException) { throw new RelayFailure(!sourceIsClient&&TrafficHealth.IsExpectedClose(ex),sourceIsClient?"Передача сетевому процессу":"Передача приложению",ex); }
                }
                // EOF closes only this direction. The peer may still owe a response.
                try { destination.Client.Shutdown(SocketShutdown.Send); } catch(SocketException) { }
            }
            catch { relay.Cancel(); throw; }
        }
        try { await Task.WhenAll(Pump(client,backend,true),Pump(backend,client,false)); }
        catch(OperationCanceledException) when(stop.IsCancellationRequested||relay.IsCancellationRequested) { }
    }
    sealed class RelayFailure(bool clientClosed,string stage,Exception inner):IOException(stage+": "+inner.GetBaseException().Message,inner)
    { public bool ClientClosed { get; }=clientClosed; }
    public static string Normalize(string header)
    {
        var lines=header.Split("\r\n"); var first=lines[0].Split(' ',3);
        if(first.Length==3)
        {
            if(first[0].Equals("CONNECT",StringComparison.OrdinalIgnoreCase)) first[1]=Authority(first[1]);
            else if(first[1].StartsWith("http://",StringComparison.OrdinalIgnoreCase))
            {
                var slash=first[1].IndexOf('/',7); var end=slash<0?first[1].Length:slash;
                first[1]="http://"+Authority(first[1][7..end])+first[1][end..];
            }
            lines[0]=string.Join(' ',first);
        }
        for(int i=1;i<lines.Length;i++)
            if(lines[i].StartsWith("Host:",StringComparison.OrdinalIgnoreCase)) lines[i]="Host: "+Authority(lines[i][5..].Trim());
        return string.Join("\r\n",lines);
    }
    static string Authority(string text)
    {
        if(text.StartsWith('[')||text.Count(c=>c==':')<2) return text;
        var split=text.LastIndexOf(':');
        if(split>0&&int.TryParse(text[(split+1)..],out var port)&&port is >0 and <=65535&&IPAddress.TryParse(text[..split],out var ip)&&ip.AddressFamily==AddressFamily.InterNetworkV6)
            return "["+text[..split]+"]:"+port;
        return text;
    }
    public void Dispose() { stop.Cancel(); listener.Stop(); foreach(var client in clients.Keys) client.Dispose(); }
}
