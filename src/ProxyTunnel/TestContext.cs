namespace ProxyTunnelPrototype;

static class TestContext
{
    // Environment overrides never disable protection during a normal GUI launch.
    public static bool Enabled => Environment.GetEnvironmentVariable("PROXY_TUNNEL_TEST_DATA")!=null&&Environment.GetCommandLineArgs().Any(a=>new[]{"--update-test","--reports-test","--vps-log-test","--log-period-test","--stability-test","--self-test","--support-test","--privacy-test","--network-test","--diagnose","--channel-test","--render-preview","--proxy-watchdog","--lease-fixture"}.Contains(a));
}




