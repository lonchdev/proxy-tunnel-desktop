using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace ProxyTunnelPrototype;

static class IntegrationTests
{
    public static int Run()
    {
        var lines=new List<string>();
        var clientLogs=new List<string>();
        var processes=new List<Process>();
        var root=Path.Combine(Settings.DataDir,"integration"); Directory.CreateDirectory(root);
        try
        {
            var s=new Settings{Host="127.0.0.1",ServerPort=25443,AllTraffic=false};
            using var network=new Network(s); network.Extract();
            var secret=Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
            bool Routed(string domain,string route)
            {
                lock(clientLogs)
                {
                    var inbound=clientLogs.LastOrDefault(l=>l.Contains("inbound connection to "+domain+":"));
                    if(inbound==null) return false;
                    var id=System.Text.RegularExpressions.Regex.Match(inbound,@"\[(\d+) ").Groups[1].Value;
                    return clientLogs.LastOrDefault(l=>l.Contains("["+id+" ")&&l.Contains("outbound/"))?.Contains(route)==true;
                }
            }
            void Start(string name,string text)
            {
                // Loopback fixture has no TUN and does not need privileged interface binding.
                if(name.Contains("client")) { var node=System.Text.Json.Nodes.JsonNode.Parse(text)!; node["route"]!["auto_detect_interface"]=false; text=node.ToJsonString(); }
                var path=Path.Combine(root,name+".json"); File.WriteAllText(path,text);
                var psi=new ProcessStartInfo(network.Engine){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true,RedirectStandardOutput=true};
                foreach(var a in new[]{"run","-c",path}) psi.ArgumentList.Add(a);
                var p=new Process{StartInfo=psi}; p.ErrorDataReceived+=(_,e)=> { if(name.Contains("client")&&e.Data!=null) lock(clientLogs) clientLogs.Add(LogPrivacy.Clean(e.Data)); }; p.OutputDataReceived+=(_,e)=> { };
                p.Start(); p.BeginErrorReadLine(); p.BeginOutputReadLine(); processes.Add(p);
            }
            Start("server",ConfigBuilder.Server(s,secret));
            Start("client",ConfigBuilder.Client(s,secret,false));
            using var front=new ProxyFront(); front.Start();
            Thread.Sleep(1200);
            foreach(var p in processes) if(p.HasExited) throw new Exception("Integration engine did not start");
            using(var http=new HttpClient(new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+ConfigBuilder.PortBase)}){Timeout=TimeSpan.FromSeconds(20)})
            {
                var result=http.GetStringAsync("https://api.ipify.org").GetAwaiter().GetResult().Trim();
                if(!IPAddress.TryParse(result,out _)) throw new Exception("Encrypted TCP response invalid");
                lines.Add("PASS: HTTPS over local SOCKS/HTTP > encrypted Shadowsocks > internet");
            }
            using(var browser=new HttpClient(new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+(ConfigBuilder.PortBase+2))}){Timeout=TimeSpan.FromSeconds(20)})
            {
                using var selected=browser.GetAsync("https://claude.ai/cdn-cgi/trace").GetAwaiter().GetResult();
                using var ordinary=browser.GetAsync("https://example.com/").GetAwaiter().GetResult();
                if(!selected.IsSuccessStatusCode||!ordinary.IsSuccessStatusCode) throw new Exception("Browser paths did not return successful responses");
                lock(clientLogs)
                {
                    if(!Routed("claude.ai","outbound/shadowsocks[vps]")) throw new Exception("Selected browser domain did not use VPS");
                    if(!Routed("example.com","outbound/direct[direct]")) throw new Exception("Unselected browser domain did not use direct route");
                }
                lines.Add("PASS: browser selected Claude domain > VPS; unselected example.com > direct");
            }
            using(var selectedFront=new ProxyFront(port:ConfigBuilder.PortBase+6,selectedProcess:name=>name=="Antigravity.exe",ownerResolver:(_,_)=>"Antigravity.exe"))
            {
                selectedFront.Start();
                using var selectedApp=new HttpClient(new HttpClientHandler{Proxy=new WebProxy("http://127.0.0.1:"+(ConfigBuilder.PortBase+6)),UseProxy=true}){Timeout=TimeSpan.FromSeconds(20)};
                using var response=selectedApp.GetAsync("https://example.com/").GetAwaiter().GetResult();
                lock(clientLogs) if(!clientLogs.Any(l=>l.Contains("outbound/shadowsocks[vps]")&&l.Contains("example.com"))) throw new Exception("Selected desktop app lost VPS route in HTTP compatibility adapter");
                lines.Add("PASS: selected desktop app retains VPS routing through compatibility adapter (injected owner metadata)");
            }
            using(var tcp=new TcpClient("127.0.0.1",ConfigBuilder.PortBase))
            {
                tcp.ReceiveTimeout=5000; tcp.SendTimeout=5000;
                using var stream=tcp.GetStream();
                stream.Write(new byte[]{5,1,0}); var hello=new byte[2]; stream.ReadExactly(hello);
                if(hello[1]!=0) throw new Exception("SOCKS authentication negotiation failed");
                using var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0)); udp.Client.ReceiveTimeout=10000;
                var port=((IPEndPoint)udp.Client.LocalEndPoint!).Port;
                stream.Write(new byte[]{5,3,0,1,127,0,0,1,(byte)(port>>8),(byte)port});
                var reply=new byte[4]; stream.ReadExactly(reply);
                if(reply[1]!=0 || reply[3]!=1) throw new Exception("SOCKS UDP associate failed");
                var bound=new byte[6]; stream.ReadExactly(bound); var target=new IPEndPoint(new IPAddress(bound.Take(4).ToArray()),bound[4]*256+bound[5]);
                if(target.Address.Equals(IPAddress.Any)) target.Address=IPAddress.Loopback;
                byte[] dns=[0x53,0x81,1,0,0,1,0,0,0,0,0,0,7,(byte)'e',(byte)'x',(byte)'a',(byte)'m',(byte)'p',(byte)'l',(byte)'e',3,(byte)'o',(byte)'r',(byte)'g',0,0,1,0,1];
                byte[] header=[0,0,0,1,1,1,1,1,0,53]; var packet=header.Concat(dns).ToArray(); udp.Send(packet,packet.Length,target);
                IPEndPoint sender=new(IPAddress.Any,0); var response=udp.Receive(ref sender);
                var offset=response[3]==1?10:22;
                if(response.Length<offset+12 || response[offset]!=0x53 || response[offset+1]!=0x81 || (response[offset+2]&0x80)==0 || (response[offset+3]&0x0f)!=0) throw new Exception("Encrypted UDP DNS reply invalid");
                lines.Add("PASS: SOCKS5 UDP > encrypted Shadowsocks UDP > DNS response");
            }
            try
            {
            using(var echo=new TcpListener(System.Net.IPAddress.IPv6Loopback,ConfigBuilder.PortBase+7))
            {
                echo.Start(); var port=((System.Net.IPEndPoint)echo.LocalEndpoint).Port;
                var server=Task.Run(async()=> { using var incoming=await echo.AcceptTcpClientAsync(); using var stream=incoming.GetStream(); var request=new byte[4]; await stream.ReadExactlyAsync(request); if(System.Text.Encoding.ASCII.GetString(request)!="ping") throw new Exception("IPv6 payload modified"); await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes("pong")); });
                using var tcp=new TcpClient("127.0.0.1",ConfigBuilder.PortBase+2); tcp.ReceiveTimeout=5000; using var wire=tcp.GetStream();
                wire.Write(System.Text.Encoding.ASCII.GetBytes($"CONNECT ::1:{port} HTTP/1.1\r\nHost: ::1:{port}\r\n\r\n"));
                var header=new List<byte>(); var tail=0;
                while(header.Count<4096) { var c=wire.ReadByte(); if(c<0) throw new Exception("IPv6 CONNECT closed prematurely"); header.Add((byte)c); tail=(tail<<8)|c; if(tail==0x0d0a0d0a) break; }
                if(!System.Text.Encoding.ASCII.GetString(header.ToArray()).Contains("200")) throw new Exception("IPv6 CONNECT was rejected");
                wire.Write(System.Text.Encoding.ASCII.GetBytes("ping")); var reply=new byte[4]; wire.ReadExactly(reply);
                if(System.Text.Encoding.ASCII.GetString(reply)!="pong") throw new Exception("IPv6 response modified");
                server.Wait(TimeSpan.FromSeconds(5)); echo.Stop();
                lines.Add("PASS: malformed IPv6 CONNECT > normalizer > mixed proxy > real IPv6 echo socket");
            }
            }
            catch(EndOfStreamException) when(clientLogs.Any(l=>l.Contains("[::1]")&&l.Contains("access permissions")))
            { lines.Add("NOT VERIFIED: Windows denied the test engine IPv6 loopback socket (WSAEACCES). No firewall or system IPv6 settings changed."); }
            front.Dispose(); processes[1].Kill(true); processes[1].WaitForExit(5000);
            var fallback=System.Text.Json.Nodes.JsonNode.Parse(ConfigBuilder.Client(s,secret,false))!;
            // Deliberately unavailable primary, without touching Windows DNS.
            fallback["dns"]!["servers"]![0]=System.Text.Json.Nodes.JsonNode.Parse("{\"type\":\"tcp\",\"tag\":\"remote-dns\",\"server\":\"127.0.0.1\",\"server_port\":1,\"detour\":\"vps\"}");
            fallback["log"]!["level"]="debug";
            lock(clientLogs) clientLogs.Clear();
            Start("fallback-client",fallback.ToJsonString());
            using var fallbackFront=new ProxyFront(); fallbackFront.Start(); Thread.Sleep(1000);
            using(var http=new HttpClient(new HttpClientHandler{Proxy=new WebProxy("http://127.0.0.1:"+(ConfigBuilder.PortBase+2)),UseProxy=true}){Timeout=TimeSpan.FromSeconds(20)})
            {
                using var response=http.GetAsync("https://example.net/").GetAwaiter().GetResult();
                if(!response.IsSuccessStatusCode) throw new Exception("DNS fallback request failed: "+response.StatusCode);
            }
            lock(clientLogs)
            {
                if(!clientLogs.Any(l=>l.Contains("evaluate(remote-dns"))||!clientLogs.Any(l=>l.Contains("route(backup-dns")))
                    throw new Exception("DNS fallback route was not observed: "+string.Join("\n",clientLogs.Where(l=>l.Contains("dns"))));
            }
            lines.Add("PASS: primary DNS deliberately unavailable; routing rules use backup DoH over encrypted VPS transport and HTTPS succeeds");
            return 0;
        }
        catch(Exception e) { lines.Add("FAILED: "+e); lock(clientLogs) lines.AddRange(clientLogs.TakeLast(60)); return 1; }
        finally
        {
            foreach(var p in processes) { try { if(!p.HasExited) { p.Kill(true); p.WaitForExit(5000); } p.Dispose(); } catch { } }
            foreach(var path in Directory.EnumerateFiles(root,"*.json")) File.Delete(path);
            File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"network-test.txt"),lines);
        }
    }
}


