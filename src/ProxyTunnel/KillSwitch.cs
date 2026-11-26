using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProxyTunnelPrototype;

public sealed record GuardRule(string Name,bool Permit,byte Weight,string? Local=null,string? Remote=null,int? Port=null,byte? Protocol=null,bool EngineOnly=false);

public static class KillSwitch
{
    // Fixed ownership GUIDs: disarming never touches another application's filters.
    static readonly Guid Provider=new("687768cb-0fee-4ded-a815-a3850bcb1f62");
    static readonly Guid Sublayer=new("fbe69322-f399-4e27-91c0-8d667ee7992c");
    static readonly Guid V4=new("c38d57d1-05a7-4c33-904f-7fbceee60e82"), V6=new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid ReceiveV4=new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), ReceiveV6=new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid Local=new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957"), Remote=new("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), Port=new("c35a604d-d22b-4e1a-91b4-68f674ee674b"), Protocol=new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), App=new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    const uint NotFound=0x80320003, Exists=0x80320009;
    static bool nativeValidated;
    static bool Testing=>TestContext.Enabled;
    static string TestState=>Path.Combine(Settings.DataDir,"guard-test-state.json");
    static Guid FilterKey(int index)=>new(SHA256.HashData(Encoding.UTF8.GetBytes("ProxyTunnelPrototype.KillSwitch.v1/"+index)).Take(16).ToArray());
    public static bool Armed
    {
        get
        {
            if(Testing) return File.Exists(TestState);
            using var engine=new WfpEngine(); var key=FilterKey(0);
            var result=NativeWfp.FwpmFilterGetByKey0(engine.Handle,ref key,out var data);
            if(result==NotFound) return false;
            Check(result); NativeWfp.FwpmFreeMemory0(ref data); return true;
        }
    }
    public static List<GuardRule> Plan(Settings settings)
    {
        var rules=new List<GuardRule> {
            new("block public IPv4",false,0,Remote:"0.0.0.0/0"), new("block public IPv6",false,0,Remote:"::/0"),
            new("allow TUN IPv4",true,15,Local:"172.29.97.1/32"), new("allow TUN IPv6",true,15,Local:"fdfe:dcba:9797::1/128"),
            new("allow loopback IPv4",true,14,Remote:"127.0.0.0/8"), new("allow loopback IPv6",true,14,Remote:"::1/128"),
            new("block physical DNS IPv4",false,10,Remote:"0.0.0.0/0",Port:53), new("block physical DNS IPv6",false,10,Remote:"::/0",Port:53),
            new("allow VPS TCP transport",true,12,Remote:settings.Host+"/32",Port:settings.ServerPort,Protocol:6),
            new("allow VPS UDP transport",true,12,Remote:settings.Host+"/32",Port:settings.ServerPort,Protocol:17),
            new("allow DHCP",true,9,Remote:"255.255.255.255/32",Port:67,Protocol:17)
        };
        foreach(var lan in new[]{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","fc00::/7","fe80::/10","ff02::/16"}) rules.Add(new("allow local network "+lan,true,3,Remote:lan));
        if(!settings.AllTraffic)
        {
            rules.Add(new("allow routing engine IPv4",true,8,Remote:"0.0.0.0/0",EngineOnly:true));
            rules.Add(new("allow routing engine IPv6",true,8,Remote:"::/0",EngineOnly:true));
        }
        return rules;
    }
    public static void Arm(Settings settings,string enginePath)
    {
        Apply(Plan(settings),enginePath);
    }
    public static List<GuardRule> UpdatePlan(Settings? recovery=null)
    {
        var rules=new List<GuardRule>{new("update block IPv4",false,0,Remote:"0.0.0.0/0"),new("update block IPv6",false,0,Remote:"::/0"),new("update loopback IPv4",true,14,Remote:"127.0.0.0/8"),new("update loopback IPv6",true,14,Remote:"::1/128")};
        if(recovery!=null)
        {
            // Only the transport can leave the PC during recovery. No LAN,
            // physical DNS, DHCP or broad routing-engine exemptions.
            rules.Add(new("update VPS TCP",true,12,Remote:recovery.Host+"/32",Port:recovery.ServerPort,Protocol:6));
            rules.Add(new("update VPS UDP",true,12,Remote:recovery.Host+"/32",Port:recovery.ServerPort,Protocol:17));
            rules.Add(new("update TUN IPv4",true,15,Local:"172.29.97.1/32"));
            rules.Add(new("update TUN IPv6",true,15,Local:"fdfe:dcba:9797::1/128"));
        }
        return rules;
    }
    internal static Guid[] UpdateLayers(bool ipv6)=>new[]{ipv6?V6:V4,ipv6?ReceiveV6:ReceiveV4};
    public static void ArmUpdateBlock(Settings? recovery=null)=>Apply(UpdatePlan(recovery),"",true);
    static void Apply(List<GuardRule> rules,string enginePath,bool update=false)
    {
        if(Testing) { Directory.CreateDirectory(Settings.DataDir); File.WriteAllText(TestState,JsonSerializer.Serialize(rules)); return; }
        using var engine=new WfpEngine(); using var arena=new Arena();
        Check(NativeWfp.FwpmTransactionBegin0(engine.Handle,0));
        try
        {
            var provider=new NativeWfp.Provider{Key=Provider,Display=new("Proxy Tunnel kill switch","Direct internet protection"),Flags=1};
            var code=NativeWfp.FwpmProviderAdd0(engine.Handle,ref provider,IntPtr.Zero); if(code!=Exists) Check(code);
            var providerPointer=arena.Struct(Provider);
            var sub=new NativeWfp.SubLayer{Key=Sublayer,Display=new("Proxy Tunnel protection","Owned traffic rules"),Flags=1,Provider=providerPointer,Weight=65500};
            code=NativeWfp.FwpmSubLayerAdd0(engine.Handle,ref sub,IntPtr.Zero); if(code!=Exists) Check(code);
            DeleteFilters(engine.Handle);
            IntPtr appBlob=IntPtr.Zero;
            if(rules.Any(r=>r.EngineOnly)) { Check(NativeWfp.FwpmGetAppIdFromFileName0(enginePath,out appBlob)); arena.Wfp(appBlob); }
            for(var i=0;i<rules.Count;i++)
            {
                var rule=rules[i]; var conditions=new List<NativeWfp.Condition>();
                var ipv6=(rule.Remote??rule.Local)!.Contains(':');
                if(rule.Local!=null) conditions.Add(Address(Local,rule.Local,arena));
                if(rule.Remote!=null) conditions.Add(Address(Remote,rule.Remote,arena));
                if(rule.Port.HasValue) conditions.Add(new(){Key=Port,Value=new(){Type=2,U16=(ushort)rule.Port.Value}});
                if(rule.Protocol.HasValue) conditions.Add(new(){Key=Protocol,Value=new(){Type=1,U8=rule.Protocol.Value}});
                if(rule.EngineOnly) conditions.Add(new(){Key=App,Value=new(){Type=12,Pointer=appBlob}});
                var filter=new NativeWfp.Filter{Key=FilterKey(i),Display=new("Proxy Tunnel: "+rule.Name,rule.Name),Flags=1,Provider=providerPointer,Layer=ipv6?V6:V4,SubLayer=Sublayer,
                    Weight=new(){Type=1,U8=rule.Weight},Count=(uint)conditions.Count,Conditions=arena.Array(conditions),Action=new(){Type=rule.Permit?0x1002u:0x1001u}};
                Check(NativeWfp.FwpmFilterAdd0(engine.Handle,ref filter,IntPtr.Zero,out _));
                if(update)
                {
                    // Also reauthorize inbound-initiated flows: their replies
                    // must not bypass a temporary outgoing-connect-only gate.
                    filter.Key=FilterKey(i+64); filter.Layer=UpdateLayers(ipv6)[1];
                    Check(NativeWfp.FwpmFilterAdd0(engine.Handle,ref filter,IntPtr.Zero,out _));
                }
            }
            Check(NativeWfp.FwpmTransactionCommit0(engine.Handle));
        }
        catch { NativeWfp.FwpmTransactionAbort0(engine.Handle); throw; }
    }
    public static void Disarm()
    {
        if(Testing) { File.Delete(TestState); return; }
        using var engine=new WfpEngine(); Check(NativeWfp.FwpmTransactionBegin0(engine.Handle,0));
        try { DeleteFilters(engine.Handle); Check(NativeWfp.FwpmTransactionCommit0(engine.Handle)); }
        catch { NativeWfp.FwpmTransactionAbort0(engine.Handle); throw; }
    }
    public static async Task ValidateNative(Settings settings,Action<string> log)
    {
        if(Testing||nativeValidated) return;
        // This probe cannot block general internet access: one UI process,
        // one remote IPv4 address, one TCP port. Rules are NON-persistent,
        // in a dynamic session, and explicitly deleted in finally as well.
        var alreadyProtected=Armed;
        if(!alreadyProtected) await WindowsNetwork.DirectConnect(settings.Host,settings.SshPort);
        using var arena=new Arena(); using var engine=new WfpEngine(true);
        var subkey=Guid.NewGuid(); var testKey=Guid.NewGuid(); var created=false;
        Check(NativeWfp.FwpmTransactionBegin0(engine.Handle,0));
        try
        {
            var sub=new NativeWfp.SubLayer{Key=subkey,Display=new("Proxy Tunnel single-connection test","Only this UI and the VPS SSH port"),Weight=65501};
            Check(NativeWfp.FwpmSubLayerAdd0(engine.Handle,ref sub,IntPtr.Zero));
            Check(NativeWfp.FwpmGetAppIdFromFileName0(Environment.ProcessPath!,out var app)); arena.Wfp(app);
            var conditions=new List<NativeWfp.Condition> {
                new(){Key=App,Value=new(){Type=12,Pointer=app}},
                Address(Remote,settings.Host+"/32",arena),
                new(){Key=Port,Value=new(){Type=2,U16=(ushort)settings.SshPort}},
                new(){Key=Protocol,Value=new(){Type=1,U8=6}}
            };
            var filter=new NativeWfp.Filter{Key=testKey,Display=new("Proxy Tunnel isolated probe","Temporary, one process and one destination port"),Layer=V4,SubLayer=subkey,
                Weight=new(){Type=1,U8=15},Count=(uint)conditions.Count,Conditions=arena.Array(conditions),Action=new(){Type=0x1001}};
            Check(NativeWfp.FwpmFilterAdd0(engine.Handle,ref filter,IntPtr.Zero,out _));
            Check(NativeWfp.FwpmTransactionCommit0(engine.Handle)); created=true;
        }
        catch { NativeWfp.FwpmTransactionAbort0(engine.Handle); throw; }
        try
        {
            var blocked=false;
            try { await WindowsNetwork.DirectConnect(settings.Host,settings.SshPort); }
            catch(System.Net.Sockets.SocketException ex) when(ex.SocketErrorCode==System.Net.Sockets.SocketError.AccessDenied) { blocked=true; }
            if(!blocked) throw new Exception("Windows не подтвердила блокировку тестового соединения. Защищённое подключение отменено.");
            await WindowsNetwork.DirectConnect(settings.Host,settings.ServerPort);
        }
        finally
        {
            if(created) { NativeWfp.FwpmFilterDeleteByKey0(engine.Handle,ref testKey); NativeWfp.FwpmSubLayerDeleteByKey0(engine.Handle,ref subkey); }
            // engine.Dispose closes the dynamic session: a second independent
            // cleanup guarantee if an explicit deletion failed.
        }
        nativeValidated=true; log("Самопроверка Windows: одно тестовое соединение заблокировано; транспорт VPS доступен; временное правило удалено.");
    }
    static void DeleteFilters(IntPtr engine)
    {
        for(int i=0;i<128;i++) { var key=FilterKey(i); var result=NativeWfp.FwpmFilterDeleteByKey0(engine,ref key); if(result!=NotFound) Check(result); }
    }
    static NativeWfp.Condition Address(Guid key,string cidr,Arena arena)
    {
        var parts=cidr.Split('/'); var ip=IPAddress.Parse(parts[0]); var bits=int.Parse(parts[1]);
        if(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var mask=bits==0?0u:uint.MaxValue<<(32-bits);
            return new(){Key=key,Value=new(){Type=256,Pointer=arena.Struct(new NativeWfp.V4Mask{Address=BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes()),Mask=mask})}};
        }
        return new(){Key=key,Value=new(){Type=257,Pointer=arena.Bytes(ip.GetAddressBytes().Concat(new[]{(byte)bits}).ToArray())}};
    }
    public static bool Simulate(List<GuardRule> plan,string local,string remote,int port,byte protocol,bool engine)
    {
        return plan.Where(r=>(r.Local==null||InCidr(local,r.Local))&&(r.Remote==null||InCidr(remote,r.Remote))&&(!r.Port.HasValue||r.Port==port)&&(!r.Protocol.HasValue||r.Protocol==protocol)&&(!r.EngineOnly||engine))
            .OrderByDescending(r=>r.Weight).FirstOrDefault()?.Permit??false;
    }
    static bool InCidr(string address,string cidr)
    {
        var p=cidr.Split('/'); var a=IPAddress.Parse(address).GetAddressBytes(); var b=IPAddress.Parse(p[0]).GetAddressBytes(); if(a.Length!=b.Length) return false;
        var bits=int.Parse(p[1]); for(int i=0;i<bits;i++) if((a[i/8]&(1<<(7-i%8)))!=(b[i/8]&(1<<(7-i%8)))) return false; return true;
    }
    static void Check(uint code) { if(code!=0) throw new Win32Exception(unchecked((int)code),"Защита Windows: код 0x"+code.ToString("X8")+". Нужен запуск от администратора; интернет не считается защищённым."); }
    sealed class WfpEngine : IDisposable
    {
        public IntPtr Handle;
        public WfpEngine(bool dynamic=false)
        {
            var session=IntPtr.Zero;
            try
            {
                if(dynamic) { session=Marshal.AllocHGlobal(Marshal.SizeOf<NativeWfp.Session>()); Marshal.StructureToPtr(new NativeWfp.Session{Flags=1},session,false); }
                Check(NativeWfp.FwpmEngineOpen0(null,10,IntPtr.Zero,session,out Handle));
            }
            finally { if(session!=IntPtr.Zero) Marshal.FreeHGlobal(session); }
        }
        public void Dispose()=>NativeWfp.FwpmEngineClose0(Handle);
    }
    sealed class Arena : IDisposable
    {
        readonly List<IntPtr> allocations=[],wfp=[];
        public IntPtr Bytes(byte[] data) { var p=Marshal.AllocHGlobal(data.Length); allocations.Add(p); Marshal.Copy(data,0,p,data.Length); return p; }
        public IntPtr Struct<T>(T value) where T:struct { var p=Marshal.AllocHGlobal(Marshal.SizeOf<T>()); allocations.Add(p); Marshal.StructureToPtr(value,p,false); return p; }
        public IntPtr Array<T>(List<T> values) where T:struct { var size=Marshal.SizeOf<T>(); var p=Marshal.AllocHGlobal(size*values.Count); allocations.Add(p); for(int i=0;i<values.Count;i++) Marshal.StructureToPtr(values[i],p+i*size,false); return p; }
        public void Wfp(IntPtr pointer)=>wfp.Add(pointer);
        public void Dispose() { foreach(var p in allocations) Marshal.FreeHGlobal(p); foreach(var p in wfp) { var q=p; NativeWfp.FwpmFreeMemory0(ref q); } }
    }
}

static class NativeWfp
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] internal struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string Name; [MarshalAs(UnmanagedType.LPWStr)] public string Description; public Display(string name,string description){Name=name;Description=description;} }
    [StructLayout(LayoutKind.Sequential)] internal struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] internal struct Session { public Guid Key; public Display Display; public uint Flags,Timeout,ProcessId; public IntPtr Sid,Username; public int Kernel; }
    [StructLayout(LayoutKind.Sequential)] internal struct Provider { public Guid Key; public Display Display; public uint Flags; public Blob Data; public IntPtr ServiceName; }
    [StructLayout(LayoutKind.Sequential)] internal struct SubLayer { public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data; public ushort Weight; }
    [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Value { [FieldOffset(0)] public int Type; [FieldOffset(8)] public IntPtr Pointer; [FieldOffset(8)] public byte U8; [FieldOffset(8)] public ushort U16; }
    [StructLayout(LayoutKind.Sequential)] internal struct Condition { public Guid Key; public int Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)] internal struct Action { public uint Type; public Guid Callout; }
    [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Context { [FieldOffset(0)] public ulong Raw; [FieldOffset(0)] public Guid Key; }
    [StructLayout(LayoutKind.Sequential)] internal struct Filter { public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data; public Guid Layer,SubLayer; public Value Weight; public uint Count; public IntPtr Conditions; public Action Action; public Context Context; public IntPtr Reserved; public ulong Id; public Value EffectiveWeight; }
    [StructLayout(LayoutKind.Sequential)] internal struct V4Mask { public uint Address,Mask; }
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] internal static extern uint FwpmEngineOpen0(string? server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] internal static extern uint FwpmProviderAdd0(IntPtr engine,ref Provider provider,IntPtr security);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] internal static extern uint FwpmSubLayerAdd0(IntPtr engine,ref SubLayer sublayer,IntPtr security);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] internal static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr filter);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] internal static extern uint FwpmGetAppIdFromFileName0(string name,out IntPtr appId);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
}
