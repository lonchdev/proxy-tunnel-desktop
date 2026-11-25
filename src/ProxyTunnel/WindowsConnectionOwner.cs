using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace ProxyTunnelPrototype;

static class WindowsConnectionOwner
{
    public static string? Find(IPEndPoint client,int proxyPort)
    {
        var size=0; var pointer=IntPtr.Zero;
        try
        {
            var result=GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);
            if(result!=122||size<=4) return null;
            pointer=Marshal.AllocHGlobal(size);
            if(GetExtendedTcpTable(pointer,ref size,false,2,5,0)!=0) return null;
            var count=Marshal.ReadInt32(pointer); var rowSize=Marshal.SizeOf<Row>();
            for(int i=0;i<count&&4+(i+1)*rowSize<=size;i++)
            {
                var row=Marshal.PtrToStructure<Row>(pointer+4+i*rowSize);
                var local=(ushort)IPAddress.NetworkToHostOrder(unchecked((short)row.LocalPort));
                var remote=(ushort)IPAddress.NetworkToHostOrder(unchecked((short)row.RemotePort));
                if(local!=client.Port||remote!=proxyPort||!IPAddress.IsLoopback(new IPAddress(BitConverter.GetBytes(row.LocalAddress)))) continue;
                using var process=Process.GetProcessById((int)row.Pid); return process.ProcessName+".exe";
            }
            return null;
        }
        catch { return null; }
        finally { if(pointer!=IntPtr.Zero) Marshal.FreeHGlobal(pointer); }
    }
    [StructLayout(LayoutKind.Sequential)] struct Row { public uint State,LocalAddress,LocalPort,RemoteAddress,RemotePort,Pid; }
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table,ref int size,[MarshalAs(UnmanagedType.Bool)]bool order,int family,int tableClass,uint reserved);
}
