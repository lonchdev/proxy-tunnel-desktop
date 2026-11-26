namespace ProxyTunnelPrototype;

internal static class DesktopBehavior
{
    // Legacy scheduled tasks have no --startup argument. Reading their enabled
    // state preserves automatic connection without forcing users to recreate them.
    internal static bool AutoConnect(bool serverReady,bool startupArgument,bool autostartEnabled)=>serverReady&&(startupArgument||autostartEnabled);
}
