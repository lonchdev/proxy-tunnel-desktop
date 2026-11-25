using System.IO;
using System.Runtime.InteropServices;

namespace ProxyTunnelPrototype;

static class PrivacyTests
{
    public static int Run()
    {
        var lines=new List<string>();
        lines.Add("Scope: policy model and mock lifecycle tests. Real WFP enforcement is qualified by a narrowly scoped native probe when the administrator launches Connect.");
        void Assert(bool success,string name) { if(!success) throw new Exception(name); lines.Add("PASS: "+name); }
        try
        {
            Assert(Marshal.SizeOf<NativeWfp.Filter>()==200&&Marshal.SizeOf<NativeWfp.Condition>()==40&&Marshal.SizeOf<NativeWfp.Session>()==72,"WFP x64 structure sizes match Windows SDK");
            Assert(Marshal.OffsetOf<NativeWfp.Filter>("Conditions").ToInt32()==120&&Marshal.OffsetOf<NativeWfp.Filter>("Context").ToInt32()==152,"WFP native field offsets");
            var s=new Settings{Host="203.0.113.10",ServerPort=24443};
            var full=KillSwitch.Plan(s);
            Assert(!KillSwitch.Simulate(full,"192.168.1.2","8.8.8.8",443,6,false),"Direct physical TCP blocked");
            Assert(!KillSwitch.Simulate(full,"192.168.1.2","8.8.8.8",3478,17,false),"Direct physical UDP/STUN blocked");
            Assert(!KillSwitch.Simulate(full,"2001:db8::2","2606:4700::1111",443,6,false),"Direct physical IPv6 blocked");
            Assert(!KillSwitch.Simulate(full,"192.168.1.2","192.168.1.1",53,17,false),"Physical LAN DNS blocked");
            Assert(KillSwitch.Simulate(full,"172.29.97.1","8.8.8.8",443,6,false),"TUN source TCP allowed");
            Assert(KillSwitch.Simulate(full,"fdfe:dcba:9797::1","2606:4700::1111",443,6,false),"TUN source IPv6 allowed");
            Assert(KillSwitch.Simulate(full,"192.168.1.2",s.Host,24443,6,true),"Encrypted VPS transport allowed");
            Assert(!KillSwitch.Simulate(full,"192.168.1.2",s.Host,22,6,true),"Other public VPS ports blocked");
            Assert(KillSwitch.Simulate(full,"127.0.0.1","127.0.0.1",18890,6,false),"Local proxy/OAuth callback allowed");
            Assert(KillSwitch.Simulate(full,"192.168.1.2","192.168.1.5",443,6,false),"Local network exception allowed");
            Assert(KillSwitch.Simulate(full,"0.0.0.0","255.255.255.255",67,17,false),"DHCP renewal allowed");
            s.AllTraffic=false; var selective=KillSwitch.Plan(s);
            Assert(KillSwitch.Simulate(selective,"192.168.1.2","8.8.8.8",443,6,true),"Selective direct route allowed only to routing engine");
            Assert(!KillSwitch.Simulate(selective,"192.168.1.2","8.8.8.8",443,6,false),"Selective mode blocks bypass by other applications");
            KillSwitch.Arm(s,"mock.exe"); Assert(KillSwitch.Armed,"Guard state survives network controller disposal");
            using(var n=new Network(s)) { } Assert(KillSwitch.Armed,"Disposing failed controller preserves guard");
            KillSwitch.Disarm(); Assert(!KillSwitch.Armed,"Explicit disconnect removes guard");
            var malformed="CONNECT 2001:67c:4e8:f002::b:443 HTTP/1.1\r\nHost: 2001:67c:4e8:f002::b:443\r\n\r\n";
            var expected="CONNECT [2001:67c:4e8:f002::b]:443 HTTP/1.1\r\nHost: [2001:67c:4e8:f002::b]:443\r\n\r\n";
            Assert(ProxyFront.Normalize(malformed)==expected,"Malformed IPv6 CONNECT from real log normalized");
            Assert(ProxyFront.Normalize(expected)==expected,"Valid IPv6 request unchanged");
            var normal="CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
            Assert(ProxyFront.Normalize(normal)==normal,"Normal domain request unchanged");
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { KillSwitch.Disarm(); File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"privacy-test.txt"),lines); }
    }
}
