using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Microsoft.Win32;

namespace ProxyTunnelPrototype;

public sealed class Network : IDisposable
{
    public Settings Settings { get; }
    public Journal Journal { get; }=new();
    public NetworkPhase Phase { get; private set; }=NetworkPhase.Off;
    public event Action<string>? Log;
    public event Action? Changed;
    public Func<string,string,bool>? ConfirmHost;
    public string State { get; private set; } = "Туннель выключен";
    public string ExitIp { get; private set; } = "—";
    public long Latency { get; private set; }
    public long? PingMs { get; private set; }
    public DateTime? LastChecked { get; private set; }
    public string ChecksSummary { get; private set; }="Подключение ещё не проверено.";
    public string ExitCountry { get; private set; }="";
    public bool Connected { get; private set; }
    public bool Busy { get; private set; }
    public DateTime? ConnectedAt { get; private set; }
    Process? process;
    IntPtr job;
    ProxyFront? proxyFront;
    public bool ProtectionArmed => KillSwitch.Armed;
    public int ConnectionLosses { get; private set; }
    bool lossRecorded;
    TaskCompletionSource<bool>? engineStarted;
    string phase="подготовка подключения";
    volatile bool wanted, disposed;
    readonly SemaphoreSlim gate = new(1,1);
    readonly object operationLock=new();
    CancellationTokenSource? operation;
    readonly CancellationTokenSource lifetime=new();
    readonly Task monitor;
    readonly RetrySchedule retry=new();
    readonly HealthPolicy healthPolicy=new();
    readonly TrafficHealth trafficHealth=new();
    readonly SemaphoreSlim vpsReadGate=new(1,1);
    public IncidentStore? Incidents { get; }
    readonly Task incidentWorker;
    readonly Func<Uplink?> readUplink;
    readonly bool subscribeToNetwork;
    readonly SemaphoreSlim wake=new(0,1);
    readonly UplinkStability uplinkStability=new();
    volatile Uplink? boundUplink;
    volatile bool suspended;
    int uplinkInvalidated;
    TimeSpan nextHealth,nextRetry;
    static TimeSpan Now=>TimeSpan.FromMilliseconds(Environment.TickCount64);
    bool diagnosticsOk=true;
    public bool CanCancel { get { lock(operationLock) return operation!=null; } }
    string Work => Path.Combine(Settings.DataDir, "engine-1.14.4");
    public string Engine => Path.Combine(Work, "sing-box.exe");

    public Network(Settings settings):this(settings,WindowsNetwork.ReadUplink,true) { }
    internal Network(Settings settings,Func<Uplink?> readUplink,bool subscribeToNetwork=false)
    {
        Settings=settings; this.readUplink=readUplink; this.subscribeToNetwork=subscribeToNetwork;
        try { Incidents=new IncidentStore(); Journal.Recorded+=Incidents.Append; }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { Warning("Хранилище отчётов о сбоях недоступно: "+ex.Message,"incident-storage"); }
        if(ProtectionArmed) { State="Защита активна после предыдущего сбоя"; Phase=NetworkPhase.Blocked; }
        if(subscribeToNetwork) { NetworkChange.NetworkAddressChanged+=AddressChanged; SystemEvents.PowerModeChanged+=PowerChanged; }
        monitor=Task.Run(MonitorLoop);
        incidentWorker=Task.Run(IncidentLoop);
    }
    void WakeMonitor() { try { wake.Release(); } catch(SemaphoreFullException) { } }
    void CancelOperation() { lock(operationLock) { try { operation?.Cancel(); } catch(ObjectDisposedException) { } } }
    void AddressChanged(object? sender,EventArgs args)
    {
        if(disposed) return;
        try { if(wanted&&boundUplink is {} previous&&previous.Key!=readUplink()?.Key) { Interlocked.Exchange(ref uplinkInvalidated,1); CancelOperation(); } WakeMonitor(); }
        catch(NetworkInformationException) { WakeMonitor(); }
    }
    void PowerChanged(object sender,PowerModeChangedEventArgs args)
    {
        if(disposed) return;
        if(args.Mode==PowerModes.Suspend) { if(wanted&&Connected) CaptureIncident("Переход компьютера в сон"); suspended=true; }
        else if(args.Mode==PowerModes.Resume) suspended=false;
        else return;
        if(wanted) { Interlocked.Exchange(ref uplinkInvalidated,1); CancelOperation(); }
        WakeMonitor();
    }
    void WaitingForNetwork(string message)
    {
        var text=message+(ProtectionArmed?" · защита остаётся активна":"");
        if(Phase!=NetworkPhase.WaitingForNetwork||State!=text) { SetState(NetworkPhase.WaitingForNetwork,text); Write(text); }
    }
    async Task<Uplink> WaitForUplink(CancellationToken token)
    {
        while(true)
        {
            token.ThrowIfCancellationRequested();
            if(Interlocked.Exchange(ref uplinkInvalidated,0)!=0) uplinkStability.Reset();
            var link=suspended?null:readUplink();
            if(uplinkStability.Ready(link,Now)) return link!;
            WaitingForNetwork(suspended?"Ожидание выхода из сна":link==null?"Ожидание Wi-Fi или кабеля":"Сеть появилась · ожидаем устойчивое подключение");
            await Task.Delay(250,token);
        }
    }
    void RequireCurrentUplink(Uplink link,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(suspended||link.Key!=readUplink()?.Key) throw new UplinkUnavailableException("Физическое подключение изменилось во время запуска. Ожидаем сеть перед новой попыткой.");
    }
    void Write(string text)
    {
        var line=Journal.Add(text); Log?.Invoke(line);
    }
    void Critical(string text,string key) { var line=Journal.Add(text,LogSeverity.Critical,key); Log?.Invoke(line); }
    void Warning(string text,string key) { var line=Journal.Add(text,LogSeverity.Warning,key); Log?.Invoke(line); }
    void Notify(string? state=null) { if(state!=null) State=state; Changed?.Invoke(); }
    void SetState(NetworkPhase state,string message) { Phase=state; Notify(message); }
    void Stage(string text) { phase=text; Notify(text+"…"); Write("Этап: "+text); }
    void CaptureIncident(string reason)
    {
        if(Incidents==null) return;
        try
        {
            var at=DateTimeOffset.Now;
            var item=Incidents.Begin(Settings.Host,Settings.ServerPort,reason,$"Фаза: {Phase}; физическое подключение: {boundUplink?.Name??"не выбрано"}; индекс: {boundUplink?.Index}; IPv4: {boundUplink?.Addresses}; шлюзы: {boundUplink?.Gateways}; режим: {(Settings.AllTraffic?"весь трафик":"выборочный")}",at,out var created);
            if(!created) return;
            _=Task.Run(()=> {
                try { Incidents.Before(item,Journal.RangeText(item.From.LocalDateTime,item.At.LocalDateTime)); Write("Зафиксирован сбой "+item.Id+". Сохраняем доступные записи за 5 минут до и после события."); }
                catch(Exception ex) { Warning("Не удалось дополнить отчёт о сбое: "+ex.Message,"incident-storage"); }
            });
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { Warning("Не удалось сохранить отчёт о сбое: "+ex.Message,"incident-storage"); }
    }
    async Task IncidentLoop()
    {
        var lastAttempt=TimeSpan.MinValue;
        try
        {
            while(!lifetime.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(15),lifetime.Token);
                if(Incidents==null||!Connected||Busy||!wanted||!File.Exists(Settings.KeyPath)||lastAttempt!=TimeSpan.MinValue&&Now-lastAttempt<TimeSpan.FromMinutes(1)) continue;
                var item=Incidents.Due(Settings.Host,Settings.ServerPort,DateTimeOffset.UtcNow); if(item==null) continue;
                lastAttempt=Now;
                try
                {
                    var report=await FetchVpsWindow(LogPeriod.All,DateTimeOffset.Now,item.From,item.Until,"","сбой "+item.Id+" · 5 минут до/после",lifetime.Token);
                    Incidents.Received(item,report); Write("Серверная диагностика для сбоя "+item.Id+" получена"+(report.ObserverAvailable?" вместе с историей наблюдателя.":"; наблюдатель на VPS пока недоступен.")); Notify();
                }
                catch(OperationCanceledException) when(lifetime.IsCancellationRequested) { throw; }
                catch(Exception ex) { Incidents.Failed(item,ex.GetBaseException().Message,DateTimeOffset.UtcNow); Write("Серверный отчёт для сбоя "+item.Id+" отложен до следующей попытки: "+LogPrivacy.Clean(ex.GetBaseException().Message)); }
            }
        }
        catch(OperationCanceledException) when(lifetime.IsCancellationRequested) { }
        catch(Exception ex) { Warning("Автоматическое получение отчётов остановлено: "+ex.Message,"incident-worker"); }
    }
    public void ReportError(Exception error) => Write("Ошибка: "+error.GetType().Name+": "+error.GetBaseException().Message);
    static Stream Resource(string name) => Assembly.GetExecutingAssembly().GetManifestResourceStream(name) ?? throw new Exception("Отсутствует компонент " + name);
    public void Extract()
    {
        Directory.CreateDirectory(Work);
        using var source=Resource("engine.exe");
        var expected=SHA256.HashData(source);
        if (File.Exists(Engine))
        {
            using var existing=File.OpenRead(Engine);
            if(SHA256.HashData(existing).SequenceEqual(expected)) return;
        }
        source.Position=0;
        using var dest=File.Create(Engine); source.CopyTo(dest);
    }
    ConnectionInfo Connection(string password)
    {
        AuthenticationMethod auth;
        if(!string.IsNullOrEmpty(password)) auth=new PasswordAuthenticationMethod(Settings.AdminUser,password);
        else
        {
            if(!File.Exists(Settings.KeyPath)) throw new Exception("Выберите SSH-ключ или введите пароль на странице «Сервер».");
            auth=new PrivateKeyAuthenticationMethod(Settings.AdminUser,new PrivateKeyFile(Settings.KeyPath));
        }
        return new ConnectionInfo(Settings.Host,Settings.SshPort,Settings.AdminUser,auth){ Timeout=TimeSpan.FromSeconds(20) };
    }
    void VerifyHost(object? sender, Renci.SshNet.Common.HostKeyEventArgs e)
    {
        var id=Settings.Host+":"+Settings.SshPort;
        var fp=e.FingerPrintSHA256;
        lock(Settings.HostKeys)
        {
            if(Settings.HostKeys.TryGetValue(id,out var old))
            {
                e.CanTrust=old==fp;
                if(!e.CanTrust) Write("Ключ SSH-сервера изменился. Соединение отклонено.");
            }
            else
            {
                e.CanTrust=ConfirmHost?.Invoke(id,fp)==true;
                if(e.CanTrust) { Settings.HostKeys[id]=fp; Settings.Save(); }
            }
        }
    }
    SshClient Ssh(ConnectionInfo info)
    {
        var client=new SshClient(info); client.HostKeyReceived+=VerifyHost;
        try { client.Connect(); return client; } catch { client.Dispose(); throw; }
    }
    static string Run(SshClient ssh,string command)
    {
        using var cmd=ssh.CreateCommand(command); cmd.CommandTimeout=TimeSpan.FromMinutes(3);
        var result=cmd.Execute();
        if(cmd.ExitStatus!=0) throw new Exception((cmd.Error+"\n"+result).Trim());
        return result.Trim();
    }
    public async Task<string> Probe(string password)
    {
        Settings.Validate();
        return await Task.Run(() => {
            using var ssh=Ssh(Connection(password));
            var result=Run(ssh,"printf 'OS: '; . /etc/os-release && printf '%s\\n' \"$PRETTY_NAME\"; printf 'Arch: '; uname -m; printf 'UID: '; id -u; if systemctl is-active --quiet proxy-tunnel-prototype; then echo 'Tunnel service: active'; else echo 'Tunnel service: not installed or inactive'; fi");
            using var script=Resource("server-install.sh"); using var reader=new StreamReader(script);
            var encoded=Convert.ToBase64String(Encoding.UTF8.GetBytes(reader.ReadToEnd()));
            result+="\n"+Run(ssh,"printf '%s' '"+encoded+"' | base64 -d | bash -n && echo 'Setup script syntax: OK'");
            Write("Проверка SSH выполнена: " + result.Replace('\n',';'));
            return result;
        });
    }
    public Task<VpsLogReport> FetchVpsLogs(LogPeriod period,DateTimeOffset at,string password,CancellationToken cancellation=default)=>FetchVpsWindow(period,at,period==LogPeriod.All?null:new DateTimeOffset(LogPeriods.Start(period,at.LocalDateTime)),period==LogPeriod.All?null:at,password,null,cancellation);
    async Task<VpsLogReport> FetchVpsWindow(LogPeriod period,DateTimeOffset at,DateTimeOffset? from,DateTimeOffset? until,string password,string? label,CancellationToken cancellation)
    {
        if(Busy) throw new InvalidOperationException("Дождитесь завершения текущего подключения или настройки VPS.");
        Settings.Validate();
        var host=Settings.Host; var port=Settings.SshPort; var user=Settings.AdminUser; var keyPath=Settings.KeyPath;
        var throughTunnel=Connected;
        if(!throughTunnel&&ProtectionArmed) throw new InvalidOperationException("Серверный журнал пока недоступен: туннель не работает, а защита блокирует прямой SSH. Повторите получение после восстановления связи.");
        string? fingerprint; lock(Settings.HostKeys) Settings.HostKeys.TryGetValue(host+":"+port,out fingerprint);
        if(fingerprint==null) throw new InvalidOperationException("Сначала подтвердите ключ сервера кнопкой «Проверить SSH».");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation,lifetime.Token); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        await vpsReadGate.WaitAsync(timeout.Token);
        try { return await Task.Run(async()=> {
            using var privateKey=string.IsNullOrEmpty(password)?new PrivateKeyFile(keyPath):null;
            AuthenticationMethod auth=privateKey!=null?new PrivateKeyAuthenticationMethod(user,privateKey):new PasswordAuthenticationMethod(user,password);
            using(auth)
            {
                var info=throughTunnel
                    ?new ConnectionInfo(host,port,user,ProxyTypes.Socks5,"127.0.0.1",ConfigBuilder.PortBase,"","",auth)
                    :new ConnectionInfo(host,port,user,auth);
                info.Timeout=TimeSpan.FromSeconds(10);
                using var ssh=new SshClient(info); var keyChanged=false;
                ssh.HostKeyReceived+=(_,e)=> { e.CanTrust=string.Equals(e.FingerPrintSHA256,fingerprint,StringComparison.Ordinal); keyChanged=!e.CanTrust; };
                try { await ssh.ConnectAsync(timeout.Token); }
                catch when(keyChanged) { throw new InvalidOperationException("Ключ SSH-сервера изменился. Получение журнала отклонено."); }
                using var clock=ssh.CreateCommand("date -u +%s.%N"); clock.CommandTimeout=TimeSpan.FromSeconds(5);
                var sent=DateTimeOffset.UtcNow; await clock.ExecuteAsync(timeout.Token); var received=DateTimeOffset.UtcNow;
                if(clock.ExitStatus!=0) throw new InvalidOperationException("Не удалось получить время VPS.");
                var offset=VpsLogs.ClockOffset(clock.Result,sent,received);
                using var command=ssh.CreateCommand(VpsLogs.Query(from,until,offset)); command.CommandTimeout=TimeSpan.FromSeconds(15);
                await command.ExecuteAsync(timeout.Token);
                var path=throughTunnel?"SSH внутри туннеля":"SSH напрямую";
                var report=VpsLogs.Parse(command.Result,command.Error,command.ExitStatus??-1,period,at,offset,received-sent,path,label);
                using var observer=ssh.CreateCommand(VpsLogs.ObserverQuery(from,until,offset)); observer.CommandTimeout=TimeSpan.FromSeconds(10);
                try { await observer.ExecuteAsync(timeout.Token); return VpsLogs.AddObserver(report,observer.Result,observer.Error,observer.ExitStatus??-1,at,offset,received-sent,path,label??LogPeriods.Label(period)); }
                catch(Exception ex) when(ex is not OperationCanceledException) { return report with {Text=report.Text+"\nИстория наблюдателя не получена: "+LogPrivacy.Clean(ex.GetBaseException().Message),ObserverError=true}; }
            }
        },timeout.Token); } finally { vpsReadGate.Release(); }
    }
    public async Task Prepare(string password)
    {
        if(!await gate.WaitAsync(0)) throw new Exception("Дождитесь завершения текущего действия.");
        Busy=true; Notify("Подготовка VPS…");
        try
        {
            Settings.Validate();
            if(process!=null) throw new Exception("Сначала отключите туннель.");
            // Preserve the existing key when reconfiguring this same endpoint.
            var secret=Settings.Ready ? Settings.ReadSecret() : Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            await Task.Run(() => {
                var info=Connection(password);
                using var ssh=Ssh(info);
                var preflight=Run(ssh,"test \"$(id -u)\" = 0 && test \"$(uname -m)\" = x86_64 && command -v systemctl >/dev/null && command -v tar >/dev/null && echo ready");
                if(preflight!="ready") throw new Exception("Нужен root-доступ к Ubuntu/Debian x86_64 с systemd.");
                Write("SSH подключён. Передача проверенного серверного компонента…");
                var temp=Run(ssh,"mktemp -d /tmp/proxy-tunnel-prototype.XXXXXXXX");
                if(!System.Text.RegularExpressions.Regex.IsMatch(temp,@"^/tmp/proxy-tunnel-prototype\.[A-Za-z0-9]+$")) throw new Exception("Некорректная временная папка сервера.");
                try
                {
                    using var sftp=new SftpClient(info); sftp.HostKeyReceived+=VerifyHost; sftp.OperationTimeout=TimeSpan.FromMinutes(3); sftp.Connect();
                    using(var archive=Resource("server.tar.gz")) sftp.UploadFile(archive,temp+"/engine.tar.gz");
                    using(var conf=new MemoryStream(Encoding.UTF8.GetBytes(ConfigBuilder.Server(Settings,secret)))) sftp.UploadFile(conf,temp+"/config.json");
                    using(var script=Resource("server-install.sh")) sftp.UploadFile(script,temp+"/install.sh");
                    sftp.Disconnect();
                    var result=Run(ssh,"bash "+temp+"/install.sh "+temp+" "+Settings.ServerPort);
                    if(!result.Contains("PT-READY")) throw new Exception("Служба не подтвердила готовность.");
                    Write("Служба VPS запущена. Разрешены TCP и UDP на выбранном порту.");
                }
                finally { try { Run(ssh,"rm -rf -- "+temp); } catch { } }
            });
            Settings.SetSecret(secret); Settings.ProvisionedHost=Settings.Host; Settings.ProvisionedPort=Settings.ServerPort; Settings.Save();
            Notify("VPS подготовлен — можно подключаться");
        }
        catch { Notify("Подготовка VPS не завершена"); throw; }
        finally { Busy=false; gate.Release(); Changed?.Invoke(); }
    }
    CancellationTokenSource BeginOperation()
    {
        var value=CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        lock(operationLock) operation=value;
        return value;
    }
    void EndOperation(CancellationTokenSource value)
    {
        lock(operationLock) if(ReferenceEquals(operation,value)) operation=null;
        value.Dispose();
    }
    public void RequestStop()
    {
        wanted=false; CancelOperation(); WakeMonitor();
    }
    public async Task Connect()
    {
        if(!await gate.WaitAsync(0)) return;
        wanted=true; Busy=true; retry.Reset(); uplinkStability.Reset(); var op=BeginOperation();
        try { await Start(op.Token); }
        catch(OperationCanceledException) when(op.IsCancellationRequested) { await StopCore(); if(wanted) { WaitingForNetwork("Подключение сети изменилось · ожидаем восстановления"); WakeMonitor(); } }
        catch(Exception ex) { await FailedStart(ex); }
        finally { EndOperation(op); Busy=false; gate.Release(); Changed?.Invoke(); }
    }
    async Task FailedStart(Exception error)
    {
        if(error is UplinkUnavailableException||error is not TunnelSafetyException&&error is not System.ComponentModel.Win32Exception&&(suspended||readUplink()==null))
        { await StopCore(); retry.Reset(); nextRetry=Now; uplinkStability.Reset(); WaitingForNetwork(error.Message); WakeMonitor(); return; }
        if(error is TunnelSafetyException or System.ComponentModel.Win32Exception) Critical(error.Message,"connection-safety");
        else Warning("Подключение не завершено на этапе «"+phase+"»: "+error.GetBaseException().Message,"connection-start");
        await StopCore();
        if(error is TunnelSafetyException) wanted=false;
        retry.Failed();
        nextRetry=Now+retry.Delay;
        if(retry.Failures>=3) { Critical("Три или более попытки подключения не удались. Нужна проверка журнала. "+error.GetBaseException().Message,"reconnect-failed"); CaptureIncident("Не удаётся восстановить канал: "+error.GetBaseException().Message); }
        SetState(ProtectionArmed?NetworkPhase.Blocked:NetworkPhase.Failed,ProtectionArmed?"Нет связи · прямой интернет заблокирован":"Нет связи с VPS");
    }
    public async Task<string> CheckChannel()
    {
        Settings.Validate(); await Task.Run(Extract);
        try
        {
            await Launch(ConfigBuilder.Client(Settings,Settings.ReadSecret(),false,WindowsNetwork.PhysicalInterface()),CancellationToken.None);
            await WaitReady(CancellationToken.None); var trace=await ExitProbe(CancellationToken.None);
            return "Exit: "+trace.Ip+"; HTTPS: "+trace.Milliseconds+" ms";
        }
        finally { await StopCore(); }
    }
    async Task Start(CancellationToken token,bool reconnect=false)
    {
        token.ThrowIfCancellationRequested(); Settings.Validate();
        if(Updates.Pending&&(!Settings.AllTraffic||!Settings.KillSwitch)) throw new TunnelSafetyException("Восстановление обновления требует полного режима с kill switch.");
        Phase=reconnect?NetworkPhase.Reconnecting:NetworkPhase.Connecting;
        if(!Settings.Ready) throw new Exception("Откройте «Сервер» и нажмите «Подготовить VPS».");
        await StopCore(); token.ThrowIfCancellationRequested();
        var link=await WaitForUplink(token);
        var foreign=WindowsNetwork.ForeignTunnel();
        if(foreign!=null) throw new TunnelSafetyException("Активен другой VPN («"+foreign+"»). Отключите его перед запуском Proxy Tunnel.");
        if(Process.GetProcessesByName("ProxyTunnel").Length>0) throw new TunnelSafetyException("Завершите исходный Proxy Tunnel, чтобы приложения не меняли маршруты одновременно.");
        await Task.Run(Extract,token); RequireCurrentUplink(link,token); boundUplink=link;
        Phase=reconnect?NetworkPhase.Reconnecting:NetworkPhase.Connecting;
        Stage("Запуск защищённого канала"); var secret=Settings.ReadSecret(); var physical=link.Name;
        Write("Основное подключение: "+(physical??"автоматический выбор"));
        if(Settings.KillSwitch)
        {
            if(Updates.Pending) KillSwitch.ArmUpdateBlock(Settings);
            Stage("Самопроверка защиты Windows"); await KillSwitch.ValidateNative(Settings,Write);
            token.ThrowIfCancellationRequested(); await Task.Run(()=> { if(Updates.Pending) KillSwitch.ArmUpdateBlock(Settings); else KillSwitch.Arm(Settings,Engine); },token);
            Write("Kill switch активен. Локальная сеть и транспорт VPS разрешены.");
        }
        RequireCurrentUplink(link,token);
        await Launch(ConfigBuilder.Client(Settings,secret,false,physical),token); await WaitReady(token);
        Stage("Проверка выхода через VPS"); var pre=await ExitProbe(token);
        await StopCore(); RequireCurrentUplink(link,token); boundUplink=link; Stage("Включение сетевого адаптера");
        await Launch(ConfigBuilder.Client(Settings,secret,true,physical),token); await WaitReady(token);
        Stage("Проверка выхода после включения адаптера"); var trace=await ExitProbe(token);
        if(Settings.AllTraffic)
        {
            Stage("Проверка общего маршрута Windows");
            using var direct=new HttpClient(new HttpClientHandler{UseProxy=false}){Timeout=Timeout.InfiniteTimeSpan};
            await ExitProber.Probe(direct,Settings.Host,token);
        }
        RequireCurrentUplink(link,token); Stage("Применение прокси браузеров");
        await Task.Run(ProxyLease.Apply,token); token.ThrowIfCancellationRequested();
        if(!ProxyLease.Owns()) throw new TunnelSafetyException("Прокси Windows не применён. Проверьте журнал восстановления настроек.");
        if(Updates.Pending)
        {
            // Both exit probes and the Windows route check above succeeded.
            // Returning to the normal full-mode guard is atomic in WFP.
            if(!Settings.AllTraffic||!Settings.KillSwitch) throw new TunnelSafetyException("Для завершения обновления нужен полный режим с kill switch.");
            KillSwitch.Arm(Settings,Engine); Updates.Complete();
            Write("Обновление завершено: выход через VPS подтверждён, обычный kill switch активен.");
        }
        Connected=true; ConnectedAt=DateTime.Now; ExitIp=trace.Ip; Latency=trace.Milliseconds;
        healthPolicy.Reset(); retry.Reset(); lossRecorded=false;
        nextHealth=Now+TimeSpan.FromSeconds(15);
        SetState(NetworkPhase.Checking,"Туннель работает · проверка DNS и сайтов"); FlushDns();
        diagnosticsOk=await VerifyServices(token);
        PingMs=await WindowsNetwork.TcpPing(Settings.Host,Settings.ServerPort).WaitAsync(token); LastChecked=DateTime.Now;
        token.ThrowIfCancellationRequested();
        var good=diagnosticsOk&&trafficHealth.Recent(Now)<3;
        SetState(good?NetworkPhase.Connected:NetworkPhase.Degraded,good?"Туннель подключён":"Туннель работает · есть предупреждения связи");
        Write("Подключено. Выход: "+ExitIp+". Режим: "+(Settings.AllTraffic?"весь интернет-трафик":"выбранные сайты и приложения"));
    }
    async Task Launch(string config,CancellationToken token)
    {
        var path=Path.Combine(Work,"active.json"); await File.WriteAllTextAsync(path,config,token);
        using var check=NewProcess("check","-c",path);
        try
        {
            check.Start(); var errors=check.StandardError.ReadToEndAsync(token); var output=check.StandardOutput.ReadToEndAsync(token);
            await check.WaitForExitAsync(token); var error=await errors; await output;
            if(check.ExitCode!=0) throw new Exception("Проверка сетевых настроек: "+error);
        }
        finally { try { if(!check.HasExited) check.Kill(true); } catch(InvalidOperationException) { } }
        token.ThrowIfCancellationRequested();
        engineStarted=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously); var ready=engineStarted;
        void EngineLine(string? line)
        {
            if(line==null) return;
            var vpsFailure=TrafficHealth.IsVpsFailure(line,Settings.Host,Settings.ServerPort);
            if(vpsFailure&&wanted) trafficHealth.Failure(Now);
            if(line.Contains("FATAL")) { Critical("Сетевой процесс: "+line,"engine-failure"); if(wanted) CaptureIncident("Сетевой процесс сообщил FATAL"); }
            else if(!ready.Task.IsCompleted||line.Contains("ERROR")) Write("Сеть: "+line);
            else if(line.Contains("outbound/")&&(line.Contains("googleapis.com")||line.Contains("antigravity.google")||line.Contains("accounts.google.com"))) Write("Маршрут Google: "+line);
            if(line.Contains("FATAL")) ready.TrySetException(new Exception("Сетевой процесс не запустился; подробности в журнале."));
            else if(line.Contains("sing-box started")) ready.TrySetResult(true);
            if(vpsFailure&&wanted&&trafficHealth.Recent(Now)>=3)
            {
                CaptureIncident("Повторяющиеся ошибки подключения к VPS");
                if(Connected) SetState(NetworkPhase.Degraded,"Туннель работает · есть сбои связи с VPS");
            }
        }
        process=NewProcess("run","-c",path); process.ErrorDataReceived+=(_,e)=>EngineLine(e.Data); process.OutputDataReceived+=(_,e)=>EngineLine(e.Data);
        var chosen=Settings.Processes(); proxyFront=new ProxyFront(log:Write,selectedProcess:!Settings.AllTraffic&&chosen.Length>0?name=>chosen.Contains(name,StringComparer.OrdinalIgnoreCase):null); proxyFront.Start();
        process.Start(); job=Native.CreateJobObject(IntPtr.Zero,null); var limits=new Native.JobLimits(); limits.Basic.LimitFlags=0x2000;
        if(job==IntPtr.Zero||!Native.SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf<Native.JobLimits>())||!Native.AssignProcessToJobObject(job,process.Handle))
            throw new TunnelSafetyException("Не удалось включить безопасное завершение сетевого процесса.");
        process.BeginErrorReadLine(); process.BeginOutputReadLine();
    }
    Process NewProcess(params string[] args)
    {
        var info=new ProcessStartInfo(Engine){UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true,RedirectStandardOutput=true,StandardErrorEncoding=Encoding.UTF8,StandardOutputEncoding=Encoding.UTF8,WorkingDirectory=Work};
        foreach(var a in args) info.ArgumentList.Add(a); return new Process{StartInfo=info};
    }
    async Task WaitReady(CancellationToken token)
    {
        var timer=Stopwatch.StartNew();
        while(timer.Elapsed<TimeSpan.FromSeconds(25))
        {
            token.ThrowIfCancellationRequested();
            if(process==null||process.HasExited) throw new Exception("Сетевой компонент остановился. Подробности — в журнале.");
            if(engineStarted?.Task.IsCompleted==true)
            {
                await engineStarted.Task;
                try
                {
                    using var tcp=new System.Net.Sockets.TcpClient(); using var attempt=CancellationTokenSource.CreateLinkedTokenSource(token); attempt.CancelAfter(1000);
                    await tcp.ConnectAsync("127.0.0.1",ConfigBuilder.PortBase,attempt.Token); token.ThrowIfCancellationRequested();
                    File.Delete(Path.Combine(Work,"active.json")); Write("Сетевой компонент готов; локальный порт доступен."); return;
                }
                catch(System.Net.Sockets.SocketException) { }
                catch(OperationCanceledException) when(!token.IsCancellationRequested) { }
            }
            await Task.Delay(150,token);
        }
        throw new TimeoutException("Сетевой компонент не стал готов за 25 секунд. Проверьте журнал запуска.");
    }
    async Task<ExitResult> ExitProbe(CancellationToken token)
    {
        using var http=new HttpClient(new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+ConfigBuilder.PortBase)}){Timeout=Timeout.InfiniteTimeSpan};
        var result=await ExitProber.Probe(http,Settings.Host,token);
        if(result.UsedFallback) Write("Резервная проверка выхода успешна: "+result.Source+". Перезапуск канала не требуется.");
        return result;
    }
    public async Task Check()
    {
        if(!await gate.WaitAsync(0)) return;
        var op=BeginOperation(); Busy=true;
        try
        {
            Settings.Validate(); SetState(NetworkPhase.Checking,"Проверка соединения…");
            PingMs=await WindowsNetwork.TcpPing(Settings.Host,Settings.ServerPort).WaitAsync(op.Token); LastChecked=DateTime.Now;
            Write(PingMs.HasValue?"Ping до VPS (TCP): "+PingMs+" мс.":"VPS не ответил на TCP-проверку."); Notify();
            if(!Connected) { SetState(ProtectionArmed?NetworkPhase.Blocked:NetworkPhase.Off,ProtectionArmed?"Защита активна · туннель выключен":"Туннель выключен"); return; }
            if(!ProxyLease.Owns()) throw new TunnelSafetyException("Прокси Windows изменён другим приложением.");
            try { var result=await ExitProbe(op.Token); ExitIp=result.Ip; Latency=result.Milliseconds; }
            catch(HttpRequestException ex) { Warning("Проверки выхода временно недоступны. Рабочий канал не перезапускается: "+ex.Message,"exit-probe-unavailable"); }
            diagnosticsOk=await VerifyServices(op.Token);
            var good=diagnosticsOk&&trafficHealth.Recent(Now)<3;
            SetState(good?NetworkPhase.Connected:NetworkPhase.Degraded,good?"Туннель подключён":"Туннель работает · есть предупреждения связи");
        }
        catch(OperationCanceledException) when(op.IsCancellationRequested) { }
        catch(TunnelSafetyException ex) { Critical(ex.Message,"route-safety"); CaptureIncident(ex.Message); wanted=false; await StopCore(); SetState(NetworkPhase.Blocked,"Проверьте маршрутизацию · подключение остановлено"); }
        finally { EndOperation(op); Busy=false; gate.Release(); Changed?.Invoke(); }
    }
    async Task<bool> VerifyServices(CancellationToken token)
    {
        var warnings=0;
        try { await WindowsNetwork.CheckDns("claude.ai").WaitAsync(token); Write("DNS Windows: ответ получен без использования кэша."); }
        catch(Exception ex) when(ex is not OperationCanceledException)
        {
            try { await WindowsNetwork.CheckDns("www.youtube.com").WaitAsync(token); Warning("DNS первого контрольного домена недоступен; резервный домен разрешается.","dns-domain-warning"); }
            catch(Exception fallback) when(fallback is not OperationCanceledException) { Interlocked.Increment(ref warnings); Critical("DNS Windows не прошёл две независимые проверки: "+fallback.Message,"dns-unavailable"); CaptureIncident("DNS Windows не прошёл две независимые проверки"); }
        }
        var targets=new[]{("Claude","https://claude.ai/cdn-cgi/trace"),("ChatGPT","https://chatgpt.com/"),("Telegram","https://web.telegram.org/"),("YouTube","https://www.youtube.com/generate_204")}
            .Where(t=>Settings.AllTraffic||Settings.Services.Any(s=>s.Name==t.Item1&&s.Web)).ToArray();
        using var browser=new HttpClient(new HttpClientHandler{Proxy=new WebProxy("http://"+ProxyLease.Endpoint),UseProxy=true,AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
        async Task Site(string label,string url,bool accountEndpoint=false)
        {
            using var request=CancellationTokenSource.CreateLinkedTokenSource(token); request.CancelAfter(8000);
            try
            {
                using var response=await browser.GetAsync(url,HttpCompletionOption.ResponseHeadersRead,request.Token); var code=(int)response.StatusCode;
                Write(label+": HTTP "+code+(accountEndpoint?". Сетевой ответ не подтверждает доступность аккаунта.":" через прокси браузеров."));
                if(code>=400&&!accountEndpoint) { Interlocked.Increment(ref warnings); Warning(label+": сервис ответил отказом; это не означает обрыв туннеля.","site-refused-"+label); }
                if(label=="Claude"&&response.IsSuccessStatusCode) { var trace=await response.Content.ReadAsStringAsync(request.Token); ExitCountry=trace.Split('\n').FirstOrDefault(l=>l.StartsWith("loc="))?[4..].Trim()??""; }
            }
            catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException)
            { token.ThrowIfCancellationRequested(); Interlocked.Increment(ref warnings); Warning(label+": проверка сайта не прошла. Канал сохраняется. "+ex.GetBaseException().Message,"site-unavailable-"+label); }
        }
        var checks=targets.Select(t=>Site(t.Item1,t.Item2)).ToList();
        if(Settings.AllTraffic||Settings.Services.Any(s=>s.Name=="Antigravity"&&(s.Web||s.Desktop)))
            checks.AddRange(new[]{"https://antigravity.google/","https://accounts.google.com/","https://cloudcode-pa.googleapis.com/"}.Select(u=>Site(new Uri(u).Host,u,true)));
        await Task.WhenAll(checks); token.ThrowIfCancellationRequested();
        ChecksSummary=warnings==0?"✓  DNS и доступность сайтов проверены":"Канал работает · предупреждений диагностики: "+warnings;
        return warnings==0;
    }
    async Task MonitorLoop()
    {
        try
        {
            while(!lifetime.IsCancellationRequested)
            {
                await wake.WaitAsync(TimeSpan.FromSeconds(3),lifetime.Token);
                if(disposed||!wanted||Busy||!await gate.WaitAsync(0)) continue;
                var op=BeginOperation();
                try
                {
                    if(!wanted) continue;
                    // Evaluate only the physical uplink. Creating our own TUN must not
                    // trigger a restart loop through NetworkAddressChanged.
                    var link=suspended?null:readUplink();
                    var invalidated=Interlocked.Exchange(ref uplinkInvalidated,0)!=0;
                    if(UplinkStability.RequiresRebind(boundUplink,link,invalidated))
                    {
                        uplinkStability.Reset(); healthPolicy.Reset(); retry.Reset(); nextRetry=Now;
                        if(process!=null)
                        {
                            CaptureIncident(suspended?"Компьютер перешёл в сон":"Изменилось или пропало физическое подключение");
                            if(!lossRecorded) { ConnectionLosses++; lossRecorded=true; }
                            Warning("Изменилось физическое подключение или компьютер вернулся из сна. Пересоздаём канал с актуальным адресом и шлюзом; правила защиты сохраняются.","uplink-changed");
                            await StopCore();
                        }
                    }
                    if(!uplinkStability.Ready(link,Now))
                    {
                        WaitingForNetwork(suspended?"Ожидание выхода из сна":link==null?"Ожидание Wi-Fi или кабеля":"Сеть появилась · ожидаем устойчивое подключение");
                        continue;
                    }
                    if(!Connected)
                    {
                        if(Settings.Reconnect&&Now>=nextRetry) { Busy=true; SetState(NetworkPhase.Reconnecting,"Переподключение…"); try { await Start(op.Token,true); } catch(OperationCanceledException) when(op.IsCancellationRequested) { await StopCore(); if(wanted) WaitingForNetwork("Подключение сети изменилось · ожидаем восстановления"); } catch(Exception ex) { await FailedStart(ex); } }
                        else if(!Settings.Reconnect) { wanted=false; SetState(ProtectionArmed?NetworkPhase.Blocked:NetworkPhase.Off,"Сеть доступна · автоматическое переподключение выключено"); }
                        continue;
                    }
                    if(Now<nextHealth) continue;
                    nextHealth=Now+TimeSpan.FromSeconds(15);
                    if(!ProxyLease.Owns()) throw new TunnelSafetyException("Настройки прокси изменены другим приложением. Нужна проверка маршрутизации.");
                    var alive=process is {HasExited:false}; var succeeded=false;
                    if(alive) try { var result=await ExitProbe(op.Token); Latency=result.Milliseconds; succeeded=true; } catch(HttpRequestException) { }
                    if(!healthPolicy.NeedsRestart(alive,succeeded))
                    {
                        if(!succeeded) { Warning("Контрольные адреса не ответили. Сохраняем канал до повторной проверки.","health-warning"); SetState(NetworkPhase.Degraded,"Канал запущен · ожидается повторная проверка"); }
                        else { var good=diagnosticsOk&&trafficHealth.Recent(Now)<3; SetState(good?NetworkPhase.Connected:NetworkPhase.Degraded,good?"Туннель подключён":"Туннель работает · есть предупреждения связи"); }
                        continue;
                    }
                    if(!alive) Critical("Сетевой процесс неожиданно завершился. Нужна проверка журнала.","engine-failure");
                    CaptureIncident(alive?"Не прошли два цикла независимых проверок канала":"Сетевой процесс завершился");
                    if(!lossRecorded) { ConnectionLosses++; lossRecorded=true; }
                    Warning("Подтверждён сбой канала по состоянию процесса или двум циклам проверок. Начинаем восстановление.","channel-unavailable");
                    await StopCore(); retry.Reset(); healthPolicy.Reset(); nextRetry=Now+retry.Delay;
                    SetState(ProtectionArmed?NetworkPhase.Blocked:NetworkPhase.Failed,ProtectionArmed?"Нет связи · интернет заблокирован":"Соединение потеряно");
                }
                catch(OperationCanceledException) when(op.IsCancellationRequested) { await StopCore(); if(wanted) WaitingForNetwork("Подключение сети изменилось · ожидаем восстановления"); }
                catch(TunnelSafetyException ex) { Critical(ex.Message,"route-safety"); CaptureIncident(ex.Message); wanted=false; await StopCore(); SetState(NetworkPhase.Blocked,"Проверьте маршруты · подключение остановлено"); }
                catch(Exception ex) { Critical("Ошибка контроллера подключения: "+ex.GetBaseException().Message,"controller-error"); }
                finally { EndOperation(op); Busy=false; gate.Release(); Changed?.Invoke(); }
            }
        }
        catch(OperationCanceledException) when(lifetime.IsCancellationRequested) { }
    }
    public async Task Disconnect()
    {
        if(Updates.Pending) throw new IOException("Восстановление после обновления не завершено. Защита сохраняется. Для намеренного отключения используйте аварийную команду.");
        RequestStop(); SetState(NetworkPhase.Stopping,"Отключение…"); await gate.WaitAsync();
        try { await StopCore(); await Task.Run(KillSwitch.Disarm); retry.Reset(); healthPolicy.Reset(); FlushDns(); SetState(NetworkPhase.Off,"Туннель выключен"); Write("Ручное отключение: защита снята, обычное подключение восстановлено."); }
        catch(Exception ex) { Critical("Не удалось завершить отключение: "+ex.Message,"disconnect-error"); throw; }
        finally { gate.Release(); Changed?.Invoke(); }
    }
    public async Task Reconfigure(Action change)
    {
        if(Updates.Pending) throw new IOException("Сначала восстановите туннель после обновления; настройки защиты не меняются.");
        await gate.WaitAsync(); Busy=true; var resume=Connected||ProtectionArmed; var op=BeginOperation();
        try { await StopCore(); change(); Settings.Save(); if(!Settings.KillSwitch) await Task.Run(KillSwitch.Disarm); if(resume) { wanted=true; await Start(op.Token); } }
        catch(OperationCanceledException) when(op.IsCancellationRequested) { await StopCore(); if(wanted) { WaitingForNetwork("Подключение сети изменилось · ожидаем восстановления"); WakeMonitor(); } }
        catch(Exception ex) { await FailedStart(ex); }
        finally { EndOperation(op); Busy=false; gate.Release(); Changed?.Invoke(); }
    }
    Task StopCore()=>Task.Run(StopEngine);
    public async Task PauseForUpdate(UpdateTransaction transaction)
    {
        if((!Connected&&!transaction.Rollback)||!Settings.AllTraffic||!Settings.KillSwitch||!ProtectionArmed) throw new IOException("Обновление требует работающего полного туннеля и включённого kill switch.");
        RequestStop(); await gate.WaitAsync();
        try
        {
            Updates.Save(transaction);
            try { await Task.Run(()=>KillSwitch.ArmUpdateBlock()); }
            catch { Updates.CancelRecovery(); wanted=Connected; throw; }
            transaction.Step="blocked";
            try { Updates.Save(transaction); } catch { await StopCore(); throw; }
            await StopCore(); SetState(NetworkPhase.Blocked,"Установка обновления · интернет заблокирован");
        }
        finally { gate.Release(); }
    }
    void StopEngine()
    {
        try { ProxyLease.Release(); } catch(Exception ex) { Critical("Не удалось восстановить прокси Windows: "+ex.Message,"proxy-restore"); }
        Connected=false; ConnectedAt=null; ExitIp="—"; proxyFront?.Dispose(); proxyFront=null;
        boundUplink=null;
        if(process!=null) { try { if(!process.HasExited) { process.Kill(true); process.WaitForExit(5000); } } catch { } process.Dispose(); process=null; }
        if(job!=IntPtr.Zero) { Native.CloseHandle(job); job=IntPtr.Zero; }
        try { File.Delete(Path.Combine(Work,"active.json")); } catch { }
    }
    static void FlushDns() { try { using var p=Process.Start(new ProcessStartInfo("ipconfig.exe","/flushdns"){UseShellExecute=false,CreateNoWindow=true}); } catch { } }
    public void Dispose()
    {
        disposed=true;
        if(subscribeToNetwork) { NetworkChange.NetworkAddressChanged-=AddressChanged; SystemEvents.PowerModeChanged-=PowerChanged; }
        RequestStop(); lifetime.Cancel(); StopEngine();
    }
}


static class Native
{
    [StructLayout(LayoutKind.Sequential)] internal struct BasicLimits { public long PerProcessUserTimeLimit,PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize,MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass,SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] internal struct IoCounters { public ulong ReadOperationCount,WriteOperationCount,OtherOperationCount,ReadTransferCount,WriteTransferCount,OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] internal struct JobLimits { public BasicLimits Basic; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit,JobMemoryLimit,PeakProcessMemoryUsed,PeakJobMemoryUsed; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern IntPtr CreateJobObject(IntPtr attributes,string? name);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool SetInformationJobObject(IntPtr job,int info,ref JobLimits limits,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseHandle(IntPtr handle);
}
