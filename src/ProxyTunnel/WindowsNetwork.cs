using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace ProxyTunnelPrototype;

// The browser proxy is a temporary lease. Its original values survive a crash;
// a small watchdog restores them if the UI process exits unexpectedly.
public sealed class ProxyLease
{
    public static string Endpoint=>"127.0.0.1:"+(ConfigBuilder.PortBase+2);
    static string LeaseFile=>Path.Combine(Settings.DataDir,"proxy-lease.json");
    public string Token { get; set; }="";
    public int ParentId { get; set; }
    public long ParentStart { get; set; }
    public int? Enable { get; set; }
    public string? Server { get; set; }
    public string? Pac { get; set; }
    public string? Bypass { get; set; }
    static ProxyLease? Read()
    {
        using var guard=new LeaseLock(); var found=false;
        foreach(var file in new[]{LeaseFile,LeaseFile+".bak"})
        {
            if(!File.Exists(file)) continue; found=true;
            try { var value=JsonSerializer.Deserialize<ProxyLease>(File.ReadAllText(file)); if(value!=null&&value.Token.Length>0) return value; }
            catch(Exception ex) when(ex is JsonException or IOException) { }
        }
        if(found) throw new IOException("Снимок настроек прокси повреждён. Автоматический сброс чужих настроек не выполнялся; нужна проверка журнала.");
        return null;
    }
    public static bool Owns()
    {
        using var k=new ProxyValues(false);
        return k.GetValue("ProxyEnable") is int value&&value==1&&k.GetValue("ProxyServer") as string==Endpoint&&string.IsNullOrEmpty(k.GetValue("AutoConfigURL") as string);
    }
    public static void Recover()
    {
        using var guard=new LeaseLock();
        var previous=Read(); if(previous==null) return;
        try { using var p=Process.GetProcessById(previous.ParentId); if(!p.HasExited&&p.StartTime.ToUniversalTime().Ticks==previous.ParentStart) return; } catch { }
        Restore(previous.Token);
    }
    public static void Apply()
    {
        using var guard=new LeaseLock();
        Recover();
        if(Read()!=null) throw new Exception("Другая копия Proxy Tunnel уже управляет прокси Windows.");
        using var k=new ProxyValues(true);
        using var parent=Process.GetCurrentProcess();
        var lease=new ProxyLease { Token=Guid.NewGuid().ToString("N"), ParentId=parent.Id, ParentStart=parent.StartTime.ToUniversalTime().Ticks,
            Enable=k.GetValue("ProxyEnable") as int?, Server=k.GetValue("ProxyServer") as string, Pac=k.GetValue("AutoConfigURL") as string, Bypass=k.GetValue("ProxyOverride") as string };
        var snapshot=JsonSerializer.Serialize(lease); AtomicFile.Write(LeaseFile,snapshot); AtomicFile.Write(LeaseFile+".bak",snapshot);
        try
        {
            var psi=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
            if(!TestContext.Enabled) foreach(var key in new[]{"PROXY_TUNNEL_TEST_DATA","PROXY_TUNNEL_TEST_PORT_BASE","PROXY_TUNNEL_TEST_PROXY_STORE"}) psi.Environment.Remove(key);
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase)) psi.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory,"ProxyTunnel-Prototype.dll"));
            psi.ArgumentList.Add("--proxy-watchdog"); psi.ArgumentList.Add(lease.Token);
            using var watcher=Process.Start(psi) ?? throw new Exception("Не удалось запустить восстановление сетевых настроек.");
            k.DeleteValue("AutoConfigURL",false);
            k.SetValue("ProxyServer",Endpoint); k.SetValue("ProxyOverride","localhost;127.*;[::1];<local>"); k.SetValue("ProxyEnable",1,RegistryValueKind.DWord);
            Notify();
        }
        catch { Restore(lease.Token, true); throw; }
    }
    static void Restore(string token,bool partial=false)
    {
        using var guard=new LeaseLock();
        var lease=Read(); if(lease==null||lease.Token!=token) return;
        // Do not overwrite settings another application changed while we ran.
        if(Owns()||partial)
        {
            using var k=new ProxyValues(true);
            void Put(string name,object? value,object? applied)
            {
                if(partial&&!Equals(k.GetValue(name),applied)) return;
                if(name=="ProxyOverride"&&!Equals(k.GetValue(name),applied)) return;
                if(value==null) k.DeleteValue(name,false); else k.SetValue(name,value,value is int?RegistryValueKind.DWord:RegistryValueKind.String);
            }
            Put("ProxyEnable",lease.Enable,1); Put("ProxyServer",lease.Server,Endpoint); Put("AutoConfigURL",lease.Pac,null); Put("ProxyOverride",lease.Bypass,"localhost;127.*;[::1];<local>"); Notify();
        }
        File.Delete(LeaseFile);
        File.Delete(LeaseFile+".bak");
    }
    public static void Release()
    {
        using var guard=new LeaseLock();
        var lease=Read(); if(lease!=null&&lease.ParentId==Environment.ProcessId) Restore(lease.Token);
    }
    public static int Watch(string token)
    {
        try
        {
            while(true)
            {
                var lease=Read(); if(lease==null||lease.Token!=token) return 0;
                try { using var parent=Process.GetProcessById(lease.ParentId); if(parent.HasExited||parent.StartTime.ToUniversalTime().Ticks!=lease.ParentStart) break; }
                catch { break; }
                Thread.Sleep(500);
            }
            Restore(token); return 0;
        }
        catch { return 1; } // The next UI startup also attempts recovery.
    }
    [DllImport("wininet.dll",SetLastError=true)] static extern bool InternetSetOption(IntPtr handle,int option,IntPtr buffer,int length);
    static void Notify() { if(ProxyValues.IsTest) return; InternetSetOption(IntPtr.Zero,39,IntPtr.Zero,0); InternetSetOption(IntPtr.Zero,37,IntPtr.Zero,0); }
    sealed class LeaseLock : IDisposable
    {
        readonly Mutex mutex;
        public LeaseLock()
        {
            var key=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(Settings.DataDir).ToUpperInvariant())))[..16];
            mutex=new Mutex(false,"Local\\ProxyTunnel.ProxyLease."+key);
            try { if(!mutex.WaitOne(5000)) { mutex.Dispose(); throw new IOException("Восстановление прокси занято другим процессом."); } }
            catch(AbandonedMutexException) { }
        }
        public void Dispose() { mutex.ReleaseMutex(); mutex.Dispose(); }
    }
}

// File-backed values exercise lease/watchdog logic without touching Windows' real
// proxy settings. This backend is only enabled inside an explicit test data folder.
sealed class ProxyValues : IDisposable
{
    const string RegistryPath=@"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    static string? TestFile=>TestContext.Enabled?Environment.GetEnvironmentVariable("PROXY_TUNNEL_TEST_PROXY_STORE"):null;
    public static bool IsTest=>TestFile!=null;
    readonly RegistryKey? key;
    public ProxyValues(bool writable) { if(!IsTest) key=writable?Registry.CurrentUser.CreateSubKey(RegistryPath):Registry.CurrentUser.OpenSubKey(RegistryPath); }
    Dictionary<string,JsonElement> Load() => File.Exists(TestFile)?JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(File.ReadAllText(TestFile!))!:[];
    public object? GetValue(string name)
    {
        if(!IsTest) return key?.GetValue(name);
        var values=Load(); if(!values.TryGetValue(name,out var value)) return null;
        return value.ValueKind==JsonValueKind.Number?value.GetInt32():value.GetString();
    }
    public void SetValue(string name,object value,RegistryValueKind kind=RegistryValueKind.Unknown)
    {
        if(!IsTest) { key!.SetValue(name,value,kind); return; }
        var values=Load(); values[name]=JsonSerializer.SerializeToElement(value); File.WriteAllText(TestFile!,JsonSerializer.Serialize(values));
    }
    public void DeleteValue(string name,bool throwOnMissing)
    {
        if(!IsTest) { key!.DeleteValue(name,throwOnMissing); return; }
        var values=Load(); values.Remove(name); File.WriteAllText(TestFile!,JsonSerializer.Serialize(values));
    }
    public void Dispose()=>key?.Dispose();
}

static class WindowsNetwork
{
    public static string? ForeignTunnel()
    {
        foreach(var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if(nic.OperationalStatus!=OperationalStatus.Up||nic.Name.Equals("ProxyTunnel",StringComparison.OrdinalIgnoreCase)) continue;
            var name=(nic.Name+" "+nic.Description).ToLowerInvariant();
            if(!new[]{"sockstunnel","happ","wireguard","wintun","amnezia","vpn","tap-windows"}.Any(name.Contains)) continue;
            if(nic.GetIPProperties().UnicastAddresses.Any(a=>a.Address.AddressFamily==AddressFamily.InterNetwork&&!IPAddress.IsLoopback(a.Address))) return nic.Name;
        }
        return null;
    }
    public static string? PhysicalInterface()=>ReadUplink()?.Name;
    internal static Uplink? ReadUplink()
    {
        try
        {
        foreach(var nic in NetworkInterface.GetAllNetworkInterfaces().OrderBy(n=>n.NetworkInterfaceType==NetworkInterfaceType.Ethernet?0:1).ThenBy(n=>n.Id,StringComparer.Ordinal))
        {
            if(nic.OperationalStatus!=OperationalStatus.Up||nic.NetworkInterfaceType is not (NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet)) continue;
            if(nic.Name.Equals("ProxyTunnel",StringComparison.OrdinalIgnoreCase)||new[]{"virtual","tap","tun","vpn","wireguard"}.Any(x=>nic.Description.Contains(x,StringComparison.OrdinalIgnoreCase))) continue;
            try
            {
                var p=nic.GetIPProperties();
                var addresses=p.UnicastAddresses.Where(a=>a.Address.AddressFamily==AddressFamily.InterNetwork&&!IPAddress.IsLoopback(a.Address)&&!a.Address.Equals(IPAddress.Any)&&!a.Address.ToString().StartsWith("169.254.")).Select(a=>a.Address.ToString()).Order().ToArray();
                var gateways=p.GatewayAddresses.Where(g=>g.Address.AddressFamily==AddressFamily.InterNetwork&&!g.Address.Equals(IPAddress.Any)).Select(g=>g.Address.ToString()).Order().ToArray();
                if(addresses.Length>0&&gateways.Length>0) return new(nic.Id,nic.Name,p.GetIPv4Properties().Index,string.Join(",",addresses),string.Join(",",gateways));
            }
            catch(NetworkInformationException) { } // Interface can disappear during enumeration.
        }
        return null;
        }
        catch(NetworkInformationException) { return null; }
    }
    public static async Task<long?> TcpPing(string host,int port)
    {
        var samples=new List<long>();
        var nic=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.Name==PhysicalInterface());
        for(int i=0;i<3;i++)
        {
            try {
                using var tcp=new TcpClient(AddressFamily.InterNetwork);
                if(nic!=null)
                {
                    var properties=nic.GetIPProperties();
                    var local=properties.UnicastAddresses.FirstOrDefault(a=>a.Address.AddressFamily==AddressFamily.InterNetwork)?.Address;
                    if(local!=null) tcp.Client.Bind(new IPEndPoint(local,0));
                    tcp.Client.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(properties.GetIPv4Properties().Index)); // Windows IP_UNICAST_IF
                }
                using var cts=new CancellationTokenSource(3000); var sw=Stopwatch.StartNew(); await tcp.ConnectAsync(host,port,cts.Token); samples.Add(sw.ElapsedMilliseconds);
            }
            catch(SocketException) { } catch(OperationCanceledException) { }
        }
        return samples.Count==0?null:samples.Order().ElementAt(samples.Count/2);
    }
    public static async Task CheckDns(string host)
    {
        await Task.Run(()=> {
            var code=DnsQuery(host,1,0x8,IntPtr.Zero,out var records,IntPtr.Zero); // DNS_QUERY_BYPASS_CACHE
            if(records!=IntPtr.Zero) DnsRecordListFree(records,1);
            if(code!=0) throw new Exception("DNS Windows не разрешил "+host+" (код "+code+").");
        }).WaitAsync(TimeSpan.FromSeconds(12));
    }
    public static async Task DirectConnect(string host,int port)
    {
        using var tcp=new TcpClient(AddressFamily.InterNetwork);
        var nic=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.Name==PhysicalInterface());
        if(nic!=null)
        {
            var props=nic.GetIPProperties(); var local=props.UnicastAddresses.First(a=>a.Address.AddressFamily==AddressFamily.InterNetwork).Address;
            tcp.Client.Bind(new IPEndPoint(local,0)); tcp.Client.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(props.GetIPv4Properties().Index));
        }
        using var timeout=new CancellationTokenSource(5000); await tcp.ConnectAsync(host,port,timeout.Token);
    }
    [DllImport("dnsapi.dll",CharSet=CharSet.Unicode,EntryPoint="DnsQuery_W")] static extern int DnsQuery(string name,ushort type,uint options,IntPtr extra,out IntPtr records,IntPtr reserved);
    [DllImport("dnsapi.dll")] static extern void DnsRecordListFree(IntPtr records,int freeType);
}
