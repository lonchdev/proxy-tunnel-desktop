using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProxyTunnelPrototype;

public sealed class ServiceRule
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool Web { get; set; } = true;
    public bool Desktop { get; set; } = true;
    public string[] Domains { get; set; } = [];
    public string[] Processes { get; set; } = [];
}

public sealed class Settings
{
    public string Host { get; set; } = "";
    public int SshPort { get; set; } = 22;
    public string AdminUser { get; set; } = "root";
    public string KeyPath { get; set; } = "";
    public int ServerPort { get; set; } = 24443;
    public bool AllTraffic { get; set; } = true;
    public bool Reconnect { get; set; } = true;
    public bool KillSwitch { get; set; } = true;
    public string Secret { get; set; } = "";
    public string ProvisionedHost { get; set; } = "";
    public int ProvisionedPort { get; set; }
    public string ExtraDomains { get; set; } = "";
    public string ExtraProcesses { get; set; } = "";
    // Optional location label supplied by the server owner.
    public string ServerLocation { get; set; } = "";
    public List<ServiceRule> Services { get; set; } = Defaults();
    public Dictionary<string,string> HostKeys { get; set; } = [];
    public bool Ready => Secret.Length > 0 && Host == ProvisionedHost && ServerPort == ProvisionedPort;
    public static string DataDir => TestContext.Enabled?Environment.GetEnvironmentVariable("PROXY_TUNNEL_TEST_DATA")!:Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Proxy Tunnel Prototype");
    public static string FilePath => Path.Combine(DataDir, "settings.json");
    public string ReadSecret() => Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(Secret), null, DataProtectionScope.CurrentUser));
    public void SetSecret(string value) => Secret = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.CurrentUser));
    public void Save()
    {
        Directory.CreateDirectory(DataDir);
        var temp = FilePath + ".new";
        File.WriteAllText(temp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, FilePath, true);
    }
    public static Settings Load()
    {
        Directory.CreateDirectory(DataDir);
        if (File.Exists(FilePath))
        {
            var loaded=JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath)) ?? throw new Exception("Не удалось прочитать настройки.");
            if(!loaded.Services.Any(s=>s.Name=="Antigravity")) loaded.Services.Add(Defaults().First(s=>s.Name=="Antigravity"));
            return loaded;
        }
        var s = new Settings();
        var original = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Proxy Tunnel");
        if (File.Exists(Path.Combine(original, "config.json")))
        {
            using var d = JsonDocument.Parse(File.ReadAllText(Path.Combine(original, "config.json")));
            s.Host = d.RootElement.GetProperty("Host").GetString() ?? "";
            s.SshPort = d.RootElement.GetProperty("SshPort").GetInt32();
            s.AdminUser = d.RootElement.GetProperty("AdminUser").GetString() ?? "root";
            var key = Path.Combine(original, "admin_rsa");
            if (File.Exists(key)) s.KeyPath = key;
        }
        var hosts = Path.Combine(original, "known_hosts.json");
        if (File.Exists(hosts)) s.HostKeys = JsonSerializer.Deserialize<Dictionary<string,string>>(File.ReadAllText(hosts)) ?? [];
        return s;
    }
    public void Validate()
    {
        if (!IPAddress.TryParse(Host, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new Exception("Введите публичный IPv4-адрес VPS, например адрес из письма хостинга.");
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any)) throw new Exception("Нужен адрес удалённого VPS.");
        if (SshPort is < 1 or > 65535 || ServerPort is < 1024 or > 65535 || SshPort == ServerPort)
            throw new Exception("Проверьте порты: SSH 1–65535, туннель 1024–65535; порты должны отличаться.");
        if (string.IsNullOrWhiteSpace(AdminUser)) throw new Exception("Введите пользователя SSH.");
        foreach (var domain in Domains())
            if (Uri.CheckHostName(domain) != UriHostNameType.Dns || domain.Contains('/') || domain.Contains(':'))
                throw new Exception("Некорректный домен: " + domain + ". Укажите только имя без https:// и пути.");
        foreach (var process in Processes())
            if (process.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || !process.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                throw new Exception("Введите имя приложения с .exe, без пути: " + process);
    }
    public string[] Domains() => Services.Where(s => s.Web).SelectMany(s => s.Domains).Concat(Lines(ExtraDomains)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    public string[] Processes() => Services.Where(s => s.Desktop).SelectMany(s => s.Processes).Concat(Lines(ExtraProcesses)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    static string[] Lines(string value) => value.Split(['\r','\n',',',';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    static List<ServiceRule> Defaults() => [
        new() { Name="Claude", Description="Сайт, настольное приложение и Claude Code", Domains=["claude.ai","claude.com","anthropic.com","claudeusercontent.com","claude.site"], Processes=["Claude.exe","claude.exe"] },
        new() { Name="ChatGPT", Description="Сайт и приложение для Windows", Domains=["chatgpt.com","openai.com","oaistatic.com","oaiusercontent.com","chatgpt.livekit.cloud"], Processes=["ChatGPT.exe"] },
        new() { Name="Telegram", Description="Веб-версия, сообщения, файлы и звонки", Domains=["telegram.org","t.me","telegram.me","telegra.ph","telesco.pe"], Processes=["Telegram.exe"] },
        new() { Name="YouTube", Description="Видео, изображения и веб-плеер", Domains=["youtube.com","youtu.be","googlevideo.com","ytimg.com","youtubei.googleapis.com","youtube-nocookie.com","ggpht.com"], Processes=[], Desktop=false },
        new() { Name="Gemini", Description="Gemini, AI Studio и CLI", Domains=["gemini.google.com","aistudio.google.com","generativelanguage.googleapis.com"], Processes=["gemini.exe"], Desktop=false },
        new() { Name="Antigravity", Description="Приложение и сервисы Google для входа и API", Domains=["antigravity.google","antigravity.google.com","accounts.google.com","googleapis.com","googleusercontent.com"], Processes=["Antigravity.exe","language_server_windows_x64.exe"] }
    ];
}

public static class ConfigBuilder
{
    public static int PortBase=>TestContext.Enabled&&int.TryParse(Environment.GetEnvironmentVariable("PROXY_TUNNEL_TEST_PORT_BASE"),out var port)?port:18888;
    public static string Client(Settings s, string password, bool tun, string? physicalInterface=null)
    {
        var rules = new List<object> {
            new { inbound=new[]{"diagnostic"}, action="route", outbound="vps" },
            new { action="sniff", timeout="300ms" },
            new { protocol="dns", action="hijack-dns" },
            new { action="resolve", strategy="ipv4_only" },
            new { ip_cidr=new[]{s.Host+"/32"}, action="route", outbound="direct" },
            new { ip_is_private=true, action="route", outbound="direct" },
            new { network="icmp", action="reject" }
        };
        if (!s.AllTraffic)
        {
            if (s.Processes().Length > 0) rules.Add(new { process_name=s.Processes(), action="route", outbound="vps" });
            if (s.Domains().Length > 0) rules.Add(new { domain_suffix=s.Domains(), action="route", outbound="vps" });
        }
        var ins = new List<object> { new { type="mixed", tag="diagnostic", listen="127.0.0.1", listen_port=PortBase }, new { type="mixed", tag="browser", listen="127.0.0.1", listen_port=PortBase+3 } };
        if (tun) ins.Add(new { type="tun", tag="tun", interface_name="ProxyTunnel", address=new[]{"172.29.97.1/30","fdfe:dcba:9797::1/126"}, mtu=1400, auto_route=true, strict_route=true, dns_mode="hijack", stack="mixed" });
        return JsonSerializer.Serialize(new {
            log=new { level="info", timestamp=true },
            dns=new {
                servers=new object[]{ new { type="https", tag="remote-dns", server="1.1.1.1", server_port=443, path="/dns-query", detour="vps" }, new { type="https", tag="backup-dns", server="8.8.8.8", server_port=443, path="/dns-query", detour="vps" } },
                rules=new object[]{new {action="evaluate",server="remote-dns",tag="primary",timeout="3s"},new {match_response="primary",response_rcode="NOERROR",action="respond"},new {match_response="primary",response_rcode="NXDOMAIN",action="respond"},new {action="route",server="backup-dns",timeout="4s"}},
                @final="backup-dns", strategy="ipv4_only", reverse_mapping=true },
            inbounds=ins,
            outbounds=new object[] {
                new { type="shadowsocks", tag="vps", server=s.Host, server_port=s.ServerPort, method="2022-blake3-aes-128-gcm", password, bind_interface=physicalInterface },
                new { type="direct", tag="direct", bind_interface=physicalInterface }
            },
            route=new { rules, @final=s.AllTraffic ? "vps" : "direct", auto_detect_interface=physicalInterface==null, default_interface=physicalInterface, default_domain_resolver=new {server="backup-dns",strategy="ipv4_only"}, find_process=true }
        }, new JsonSerializerOptions{WriteIndented=true,DefaultIgnoreCondition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull});
    }
    public static string Server(Settings s, string password) => JsonSerializer.Serialize(new {
        log=new { level="warn", timestamp=true },
        inbounds=new[]{new { type="shadowsocks", tag="secure", listen="::", listen_port=s.ServerPort, method="2022-blake3-aes-128-gcm", password }},
        outbounds=new[]{new { type="direct", tag="direct" }}
    });
}
