using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

namespace ProxyTunnelPrototype;

public partial class MainWindow : Window
{
    readonly Settings settings;
    readonly Network network;
    readonly System.Windows.Forms.NotifyIcon tray;
    readonly DispatcherTimer clock;
    bool loading=true, working, closing;
    List<ServiceRule> draftRules=[];
    string selectionKey="";
    bool journalQueued;
    CancellationTokenSource? updateOperation;
    DateTime nextJournalRefresh;
    LogPeriod copyPeriod=LogPeriod.All;
    LogPeriod vpsPeriod=LogPeriod.Hour;
    CancellationTokenSource? vpsLogOperation;
    CancellationTokenSource? copyLogOperation;
    VpsLogReport? vpsLogReport;
    public MainWindow(Settings config, bool preview=false)
    {
        InitializeComponent(); settings=config; network=new Network(settings);
        network.Changed+=()=>Dispatcher.BeginInvoke(Update);
        network.Journal.Changed+=JournalChanged;
        network.ConfirmHost=(host,key)=>Dispatcher.Invoke(()=>MessageBox.Show(this,"Первое подключение к "+host+".\n\nОтпечаток SSH:\n"+key+"\n\nСверьте его в консоли хостинга, затем подтвердите доверие серверу.","Ключ VPS",MessageBoxButton.YesNo,MessageBoxImage.Question)==MessageBoxResult.Yes);
        HostBox.Text=settings.Host; SshPortBox.Text=settings.SshPort.ToString(); UserBox.Text=settings.AdminUser;
        KeyBox.Text=settings.KeyPath; TunnelPortBox.Text=settings.ServerPort.ToString();
        LocationBox.Text=settings.ServerLocation;
        AllTrafficBox.IsChecked=settings.AllTraffic; ReconnectBox.IsChecked=settings.Reconnect;
        KillSwitchBox.IsChecked=settings.KillSwitch;
        DomainsBox.Text=settings.ExtraDomains; ProcessesBox.Text=settings.ExtraProcesses;
        RenderJournal();
        AutostartBox.IsChecked=Autostart.Enabled; BuildServices(); loading=false; RefreshMode(); ShowPage("overview"); Update();
        using var iconStream=System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico")!;
        tray=new System.Windows.Forms.NotifyIcon { Icon=new System.Drawing.Icon(iconStream),Text="Proxy Tunnel · выключен",Visible=!preview };
        var menu=new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Открыть Proxy Tunnel",null,(_,_)=>Dispatcher.Invoke(Restore));
        menu.Items.Add("Выключить туннель",null,async (_,_)=>await Action(()=>network.Disconnect()));
        menu.Items.Add("Выход",null,(_,_)=>Dispatcher.Invoke(Close));
        tray.ContextMenuStrip=menu; tray.DoubleClick+=(_,_)=>Dispatcher.Invoke(Restore);
        clock=new DispatcherTimer{Interval=TimeSpan.FromSeconds(1)}; clock.Tick+=(_,_)=> { Update(); if(DateTime.Now>=nextJournalRefresh) { nextJournalRefresh=DateTime.Now.AddMinutes(1); try { network.Journal.Maintain(); } catch(Exception ex) { network.ReportError(ex); } if(LogPage.Visibility==Visibility.Visible) RenderJournal(); } }; clock.Start();
        Closing+=OnClosing;
        StateChanged+=(_,_)=> { if(WindowState==WindowState.Minimized) { Hide(); tray.Visible=true; } };
        if(!settings.Ready) ShowNotice("Для первого подключения подготовьте VPS на странице «Сервер».");
        else if(network.ProtectionArmed) ShowNotice("После предыдущего сбоя сохранена блокировка прямого интернета. Подключитесь к VPS или нажмите «Отключить защиту».");
    }
    void BuildServices()
    {
        ServiceRows.Children.Clear();
        draftRules=System.Text.Json.JsonSerializer.Deserialize<List<ServiceRule>>(System.Text.Json.JsonSerializer.Serialize(settings.Services))!;
        foreach(var rule in draftRules)
        {
            var row=new Grid { Margin=new Thickness(0,14,0,14) };
            row.ColumnDefinitions.Add(new ColumnDefinition()); row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(85)}); row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(130)});
            var name=new StackPanel(); name.Children.Add(new TextBlock { Text=rule.Name,FontSize=17,FontWeight=FontWeights.SemiBold });
            name.Children.Add(new TextBlock{Text=rule.Description,Foreground=new SolidColorBrush(Color.FromRgb(117,129,120)),FontSize=11,Margin=new Thickness(0,5,12,0),TextWrapping=TextWrapping.Wrap}); row.Children.Add(name);
            var web=new CheckBox{Content="Веб",IsChecked=rule.Web,VerticalAlignment=VerticalAlignment.Center}; Grid.SetColumn(web,1); row.Children.Add(web);
            web.Checked+=(_,_)=>rule.Web=true; web.Unchecked+=(_,_)=>rule.Web=false;
            if(rule.Processes.Length>0)
            {
                var desktop=new CheckBox{Content="Приложение",IsChecked=rule.Desktop,VerticalAlignment=VerticalAlignment.Center}; Grid.SetColumn(desktop,2); row.Children.Add(desktop);
                desktop.Checked+=(_,_)=>rule.Desktop=true; desktop.Unchecked+=(_,_)=>rule.Desktop=false;
            }
            ServiceRows.Children.Add(row);
            ServiceRows.Children.Add(new Border{Height=1,Background=new SolidColorBrush(Color.FromRgb(236,240,234))});
        }
    }
    void Navigate(object sender,RoutedEventArgs e) => ShowPage((string)((Button)sender).Tag);
    public void ShowPage(string page)
    {
        network.Journal.SetVisible(page=="log");
        if(page=="log") { RenderJournal(); Dispatcher.BeginInvoke(()=> { if(LogList.Items.Count>0) LogList.ScrollIntoView(LogList.Items[^1]); },DispatcherPriority.ContextIdle); }
        var entries=new[]{("overview","Обзор",OverviewPage,OverviewNav),("services","Сервисы",ServicesPage,ServicesNav),("server","Сервер",ServerPage,ServerNav),("log","Журнал",LogPage,LogNav),("settings","Настройки",SettingsPage,SettingsNav)};
        foreach(var (key,title,panel,button) in entries)
        {
            panel.Visibility=key==page?Visibility.Visible:Visibility.Collapsed;
            button.Background=key==page?new SolidColorBrush(Color.FromRgb(223,239,216)):Brushes.Transparent;
            button.FontWeight=key==page?FontWeights.SemiBold:FontWeights.Normal;
            if(key==page) PageTitle.Text=title;
        }
    }
    void ModeChanged(object sender,RoutedEventArgs e) { if(!loading) RefreshMode(); }
    void RefreshMode()
    {
        var all=AllTrafficBox.IsChecked==true;
        ModeNote.Text=all?"Выбран режим для всего интернет-трафика.":"Через VPS идут только выбранные сайты и приложения. Остальной интернет — напрямую.";
        AllModeNotice.Visibility=all?Visibility.Visible:Visibility.Collapsed;
        ServiceRows.IsEnabled=!all; ServiceRows.Opacity=all?0.4:1;
        CustomRules.IsEnabled=!all; CustomRules.Opacity=all?0.4:1;
    }
    void Update()
    {
        if(!IsInitialized) return;
        var incident=network.Incidents?.Latest;
        SaveIncidentButton.IsEnabled=incident!=null;
        IncidentStatus.Text=incident==null?"Зафиксированных сбоев пока нет.":$"Сбой {incident.Id} · {incident.At.LocalDateTime:dd.MM HH:mm} · "+(DateTimeOffset.UtcNow<incident.Until?"собираются записи после события":incident.ServerStatus);
        ConnectionTitle.Text=network.State; FooterStatus.Text=network.State;
        ServerSummary.Text=string.IsNullOrWhiteSpace(settings.Host)?"Сначала добавьте ваш сервер":settings.ServerLocation+"  /  "+settings.Host;
        var protectedNow=network.ProtectionArmed;
        TopStatus.Text=network.Phase switch {NetworkPhase.WaitingForNetwork=>"●  Ожидание сети",NetworkPhase.Checking=>"●  Проверка…",NetworkPhase.Degraded=>"●  Есть предупреждения",NetworkPhase.Stopping=>"●  Отключение…",NetworkPhase.Reconnecting=>"●  Переподключение…",_=>network.Busy?"●  Подключение…":network.Connected?"●  Подключён":protectedNow?"●  Защита активна":"●  Выключен"};
        ProtectionText.Text=protectedNow?"Kill switch активен · прямой выход защищён":"Kill switch выключен";
        ProtectionText.Foreground=protectedNow?Brushes.DarkGreen:Brushes.Gray;
        ReleaseProtectionButton.Visibility=protectedNow&&!network.Connected?Visibility.Visible:Visibility.Collapsed;
        LossText.Text="Потери связи в сеансе: "+network.ConnectionLosses;
        TopStatus.Foreground=network.Phase==NetworkPhase.Degraded?Brushes.DarkOrange:network.Connected?new SolidColorBrush(Color.FromRgb(23,106,72)):new SolidColorBrush(Color.FromRgb(97,115,101));
        ConnectButton.Content=network.Connected?"Отключить":network.CanCancel||network.Phase==NetworkPhase.WaitingForNetwork?"Отменить подключение":"Подключиться";
        ConnectButton.IsEnabled=network.CanCancel||(!working&&!network.Busy);
        ExitIp.Text=network.ExitIp; Latency.Text=network.PingMs.HasValue?network.PingMs+" мс":"—";
        PingUpdated.Text=network.LastChecked.HasValue?"обновлён "+network.LastChecked.Value.ToString("HH:mm:ss"):"ещё не измерен";
        Uptime.Text=network.ConnectedAt.HasValue?(DateTime.Now-network.ConnectedAt.Value).ToString(@"hh\:mm\:ss"):"—";
        ModeHeading.Text=settings.AllTraffic?"Весь интернет — через ваш VPS":"Только выбранные сервисы";
        ModeDescription.Text=network.Connected
            ? settings.AllTraffic?"Весь интернет-трафик браузеров и приложений идёт через туннель. Вы можете изменить это в настройках.":"Выбранные сайты и приложения используют VPS. Остальные соединения идут напрямую."
            : settings.AllTraffic?"После подключения интернет-трафик браузеров и приложений пойдёт через VPS.":"После подключения выбранные сайты и приложения будут использовать VPS.";
        CheckSummary.Text=network.Connected?network.ChecksSummary:network.LastChecked.HasValue?"Последняя проверка · "+network.LastChecked.Value.ToString("HH:mm:ss"):"Подключение ещё не проверено.";
        ModeCard.Visibility=settings.AllTraffic?Visibility.Visible:Visibility.Collapsed;
        OverviewServicesCard.Visibility=settings.AllTraffic?Visibility.Collapsed:Visibility.Visible;
        UpdateOverviewServices();
        ProvisionStatus.Text=settings.Ready?"✓  Защищённый канал VPS настроен":"○  Требуется подготовка VPS";
        if(tray!=null) tray.Text=network.Connected?"Proxy Tunnel · подключён":"Proxy Tunnel · выключен";
    }
    void ReadServer()
    {
        if(network.Connected || network.Busy || network.ProtectionArmed) throw new Exception("Перед изменением параметров сервера отключите туннель и защиту.");
        if(!int.TryParse(SshPortBox.Text,out var ssh) || !int.TryParse(TunnelPortBox.Text,out var port)) throw new Exception("Порт должен быть числом.");
        settings.Host=HostBox.Text.Trim(); settings.SshPort=ssh; settings.ServerPort=port;
        settings.AdminUser=UserBox.Text.Trim(); settings.KeyPath=KeyBox.Text.Trim(); settings.ServerLocation=LocationBox.Text.Trim(); settings.Validate(); settings.Save();
    }
    async Task Action(Func<Task> action)
    {
        if(working) return;
        working=true; NoticeBox.Visibility=Visibility.Collapsed; Update();
        try { await action(); }
        catch(Exception ex) { network.ReportError(ex); ShowNotice(Friendly(ex)); }
        finally { working=false; Update(); }
    }
    static string Friendly(Exception ex)
    {
        if(ex is Renci.SshNet.Common.SshAuthenticationException) return "SSH отклонил вход. Проверьте пользователя, пароль или выбранный ключ.";
        if(ex is System.Net.Http.HttpRequestException || ex is TaskCanceledException) return "Не удалось проверить интернет через VPS. Проверьте доступность сервера и порта туннеля. Подробности — в журнале.";
        return ex.Message;
    }
    void ShowNotice(string text) { NoticeText.Text=text; NoticeBox.Visibility=Visibility.Visible; }
    async void ToggleConnection(object sender,RoutedEventArgs e)
    {
        if(network.CanCancel||network.Connected||network.Phase==NetworkPhase.WaitingForNetwork)
        {
            try { await network.Disconnect(); } catch(Exception ex) { network.ReportError(ex); ShowNotice(ex.Message); } Update(); return;
        }
        await Action(async()=> {
        if(network.Connected) await network.Disconnect();
        else if(!settings.Ready) { ShowPage("server"); ShowNotice("Нажмите «Подготовить VPS», затем возвращайтесь к подключению."); }
        else await network.Connect();
        });
    }
    async void CheckConnection(object sender,RoutedEventArgs e) => await Action(()=>network.Check());
    async void ProbeServer(object sender,RoutedEventArgs e) => await Action(async()=> {
        ReadServer(); var password=Password.Password; Password.Clear();
        var result=await network.Probe(password); ShowNotice("SSH доступен. "+result.Replace('\n',';'));
    });
    async void PrepareServer(object sender,RoutedEventArgs e) => await Action(async()=> {
        ReadServer();
        if(MessageBox.Show(this,"На VPS "+settings.Host+" будет добавлена служба Proxy Tunnel Prototype и открыт порт "+settings.ServerPort+" TCP/UDP.\n\nПосле подключения приложение создаст сетевой адаптер Windows. Исходный tinyproxy и настройки SSH сервера сохранятся.\n\nПодготовить VPS?","Подготовка вашего сервера",MessageBoxButton.YesNo,MessageBoxImage.Question)!=MessageBoxResult.Yes) return;
        var password=Password.Password; Password.Clear();
        await network.Prepare(password); ShowNotice("VPS подготовлен. Откройте «Обзор» и нажмите «Подключиться».");
    });
    async void SaveServer(object sender,RoutedEventArgs e) => await Action(()=> { ReadServer(); ShowNotice("Параметры сервера сохранены."); return Task.CompletedTask; });
    void ChooseKey(object sender,RoutedEventArgs e)
    {
        var dialog=new OpenFileDialog{Title="Выберите закрытый SSH-ключ",Filter="SSH-ключ|*.*"};
        if(dialog.ShowDialog(this)==true) KeyBox.Text=dialog.FileName;
    }
    async void SaveOptions(object sender,RoutedEventArgs e) => await Action(async()=> {
        Autostart.Set(AutostartBox.IsChecked==true);
        await network.Reconfigure(()=> { settings.AllTraffic=AllTrafficBox.IsChecked==true; settings.Reconnect=ReconnectBox.IsChecked==true; settings.KillSwitch=KillSwitchBox.IsChecked==true; });
        RefreshMode(); ShowNotice("Настройки сохранены.");
    });
    async void SaveRules(object sender,RoutedEventArgs e) => await Action(async()=> {
        var candidate=System.Text.Json.JsonSerializer.Deserialize<Settings>(System.Text.Json.JsonSerializer.Serialize(settings))!;
        candidate.ExtraDomains=DomainsBox.Text; candidate.ExtraProcesses=ProcessesBox.Text; candidate.Services=draftRules; candidate.Validate();
        await network.Reconfigure(()=> { settings.ExtraDomains=candidate.ExtraDomains; settings.ExtraProcesses=candidate.ExtraProcesses;
            settings.Services=System.Text.Json.JsonSerializer.Deserialize<List<ServiceRule>>(System.Text.Json.JsonSerializer.Serialize(draftRules))!; });
        ShowNotice("Правила сохранены.");
    });
    async void ReleaseProtection(object sender,RoutedEventArgs e) => await Action(()=>network.Disconnect());
    void ExportLog(object sender,RoutedEventArgs e)
    {
        var dialog=new SaveFileDialog{Title="Сохранить журнал",FileName="ProxyTunnel-log.txt",Filter="Текстовый файл|*.txt"};
        if(dialog.ShowDialog(this)==true) { try { File.WriteAllText(dialog.FileName,network.Journal.ExportText()); } catch(Exception ex) { ShowNotice(ex.Message); } }
    }
    async void CopyLogs(object sender,RoutedEventArgs e)
    {
        if(copyLogOperation!=null) { copyLogOperation.Cancel(); return; }
        using var operation=new CancellationTokenSource(); copyLogOperation=operation;
        var period=copyPeriod; var at=DateTimeOffset.Now;
        CopyLogsButton.Content="Отменить копирование"; CopyPeriodButton.IsEnabled=false;
        try
        {
            var pc=await Task.Run(()=>network.Journal.CopyText(period,at.LocalDateTime),operation.Token);
            VpsLogReport? server=null; string? error=null;
            try { server=await network.FetchVpsLogs(period,at,"",operation.Token); }
            catch(OperationCanceledException) when(operation.IsCancellationRequested) { throw; }
            catch(Exception ex) { error=ex is OperationCanceledException?"Истекло время ожидания VPS.":ex.GetBaseException().Message; }
            if(closing||operation.IsCancellationRequested) return;
            Clipboard.SetText(ReportBundle.Compose(period,at,pc,server,error));
            ShowNotice(server==null?"Логи ПК скопированы. Серверная часть не получена — причина указана в отчёте.":server.Truncated||server.ObserverError?"Общий отчёт скопирован; серверная часть неполная — подробности внутри.":"Общий отчёт ПК + VPS скопирован · "+LogPeriods.Label(period));
        }
        catch(OperationCanceledException) { if(!closing) ShowNotice("Копирование отменено; буфер обмена не изменён."); }
        catch(Exception ex) { ShowNotice("Не удалось скопировать логи: "+ex.Message); }
        finally { copyLogOperation=null; if(!closing) { CopyLogsButton.Content="Копировать логи"; CopyPeriodButton.IsEnabled=true; } }
    }
    void SaveIncident(object sender,RoutedEventArgs e)
    {
        var incident=network.Incidents?.Latest; if(incident==null) return;
        var dialog=new SaveFileDialog{Title="Сохранить отчёт о сбое",FileName="ProxyTunnel-incident-"+incident.Id+".zip",Filter="Архив отчёта|*.zip"};
        if(dialog.ShowDialog(this)==true) try { network.Incidents!.Export(incident.Id,dialog.FileName); } catch(Exception ex) { ShowNotice(ex.Message); }
    }
    void OpenCopyPeriod(object sender,RoutedEventArgs e)
    {
        CopyPeriodButton.ContextMenu.PlacementTarget=CopyPeriodButton;
        CopyPeriodButton.ContextMenu.Placement=System.Windows.Controls.Primitives.PlacementMode.Bottom;
        CopyPeriodButton.ContextMenu.IsOpen=true;
    }
    void SelectCopyPeriod(object sender,RoutedEventArgs e)
    {
        var item=(MenuItem)sender; copyPeriod=Enum.Parse<LogPeriod>((string)item.Tag);
        foreach(MenuItem option in CopyPeriodButton.ContextMenu.Items) option.IsChecked=ReferenceEquals(option,item);
        CopyPeriodButton.Content=LogPeriods.Label(copyPeriod)+" ▾";
        CopyPeriodButton.ToolTip="Период копирования: "+item.Header;
    }
    void OpenVpsPeriod(object sender,RoutedEventArgs e)
    {
        VpsPeriodButton.ContextMenu.PlacementTarget=VpsPeriodButton;
        VpsPeriodButton.ContextMenu.Placement=System.Windows.Controls.Primitives.PlacementMode.Bottom;
        VpsPeriodButton.ContextMenu.IsOpen=true;
    }
    void SelectVpsPeriod(object sender,RoutedEventArgs e)
    {
        var item=(MenuItem)sender; vpsPeriod=Enum.Parse<LogPeriod>((string)item.Tag);
        foreach(MenuItem option in VpsPeriodButton.ContextMenu.Items) option.IsChecked=ReferenceEquals(option,item);
        VpsPeriodButton.Content=LogPeriods.Label(vpsPeriod)+" ▾";
    }
    async void FetchVpsLogs(object sender,RoutedEventArgs e)
    {
        if(vpsLogOperation!=null) { vpsLogOperation.Cancel(); return; }
        using var operation=new CancellationTokenSource(); vpsLogOperation=operation;
        FetchVpsLogsButton.Content="Отменить получение"; VpsPeriodButton.IsEnabled=false;
        vpsLogReport=null; SaveVpsLogsButton.IsEnabled=false; VpsLogsText.Clear(); VpsLogsText.Visibility=Visibility.Collapsed;
        var period=vpsPeriod; var at=DateTimeOffset.Now;
        var password=Password.Password; Password.Clear();
        VpsLogsStatus.Text="Получение журнала по SSH…";
        try
        {
            var result=await network.FetchVpsLogs(period,at,password,operation.Token);
            if(closing) return;
            vpsLogReport=result; VpsLogsText.Text=result.Text; VpsLogsText.Visibility=Visibility.Visible; SaveVpsLogsButton.IsEnabled=true;
            VpsLogsStatus.Text=$"Получено событий: {result.Entries} · {LogPeriods.Label(period)} · {result.RetrievedAt:HH:mm:ss}"+(result.Truncated?" · отчёт ограничен по размеру":"")+(result.ObserverError?" · история наблюдателя не получена":"");
        }
        catch(OperationCanceledException) { if(!closing) VpsLogsStatus.Text=operation.IsCancellationRequested?"Получение отменено.":"Время ожидания VPS истекло. Повторите после восстановления связи."; }
        catch(Exception ex) { if(!closing) { VpsLogsStatus.Text="Журнал не получен: "+LogPrivacy.Clean(ex.GetBaseException().Message); network.ReportError(ex); } }
        finally { vpsLogOperation=null; if(!closing) { FetchVpsLogsButton.Content="Получить логи VPS"; VpsPeriodButton.IsEnabled=true; } }
    }
    void SaveVpsLogs(object sender,RoutedEventArgs e)
    {
        if(vpsLogReport==null) return;
        var dialog=new SaveFileDialog{Title="Сохранить журнал VPS",FileName="ProxyTunnel-VPS-log.txt",Filter="Текстовый файл|*.txt"};
        if(dialog.ShowDialog(this)==true) try { File.WriteAllText(dialog.FileName,vpsLogReport.Text); } catch(Exception ex) { ShowNotice(ex.Message); }
    }
    void JournalChanged()
    {
        if(closing) return;
        Dispatcher.BeginInvoke(()=> {
            if(journalQueued||closing) return; journalQueued=true;
            Dispatcher.BeginInvoke(()=> { journalQueued=false; if(!closing) RenderJournal(); },DispatcherPriority.Background);
        });
    }
    void RenderJournal()
    {
        LogList.ItemsSource=network.Journal.Snapshot().Select(r=>new {Text=r.Display,Color=r.Severity==LogSeverity.Critical?Brushes.Firebrick:r.Severity==LogSeverity.Warning?Brushes.DarkGoldenrod:new SolidColorBrush(Color.FromRgb(50,65,56))}).ToArray();
        var count=network.Journal.UnreadCount;
        IssueIndicator.Visibility=count>0?Visibility.Visible:Visibility.Collapsed;
        IssueCountBubble.Visibility=count>1?Visibility.Visible:Visibility.Collapsed;
        IssueCount.Text=count>99?"99+":count.ToString();
        IssueIndicator.ToolTip="Непросмотренных проблем для проверки: "+count+". Откройте журнал и скопируйте логи.";
    }
    public void ReportStartupProblem(string text) => network.Journal.Add("Не удалось восстановить прокси Windows: "+text,LogSeverity.Critical,"proxy-restore");
    void UpdateOverviewServices()
    {
        var key=string.Join("|",settings.Services.Select(s=>s.Name+s.Web+s.Desktop))+settings.ExtraDomains+settings.ExtraProcesses;
        if(key==selectionKey) return; selectionKey=key; OverviewServiceRows.Children.Clear();
        foreach(var rule in settings.Services.Where(s=>s.Web||s.Desktop))
        {
            var panel=new StackPanel(); panel.Children.Add(new TextBlock{Text=rule.Name,FontSize=17,FontWeight=FontWeights.SemiBold});
            panel.Children.Add(new TextBlock{Text=rule.Web&&rule.Desktop?"Веб и приложение":rule.Web?"Веб":"Приложение",Foreground=new SolidColorBrush(Color.FromRgb(112,129,114)),FontSize=12,Margin=new Thickness(0,6,0,0)});
            OverviewServiceRows.Children.Add(new Border{Child=panel,Background=new SolidColorBrush(Color.FromRgb(242,248,238)),BorderBrush=new SolidColorBrush(Color.FromRgb(224,235,219)),BorderThickness=new Thickness(1),CornerRadius=new CornerRadius(10),Padding=new Thickness(12),Margin=new Thickness(0,0,10,10),MinWidth=120});
        }
        var extras=settings.ExtraDomains.Trim().Length>0||settings.ExtraProcesses.Trim().Length>0;
        if(extras) OverviewServiceRows.Children.Add(new TextBlock{Text="+ Свои домены и приложения",Margin=new Thickness(0,12,0,0),Foreground=Brushes.DarkGreen});
        if(OverviewServiceRows.Children.Count==0) OverviewServiceRows.Children.Add(new TextBlock{Text="Сервисы пока не выбраны. Добавьте их в настройках.",TextWrapping=TextWrapping.Wrap});
    }
    void Restore() { Show(); WindowState=WindowState.Normal; Activate(); }
    async void OnClosing(object? sender,System.ComponentModel.CancelEventArgs e)
    {
        if(closing) return;
        e.Cancel=true;
        if((working || network.Busy)&&!network.CanCancel) { ShowNotice("Дождитесь завершения настройки сервера перед выходом."); Restore(); return; }
        closing=true; vpsLogOperation?.Cancel(); copyLogOperation?.Cancel(); clock.Stop();
        try { if(!Updates.Pending) await network.Disconnect(); } catch(Exception ex) { closing=false; clock.Start(); network.ReportError(ex); ShowNotice("Выход не завершён: "+ex.Message); return; }
        network.Dispose(); tray.Visible=false; tray.Dispose();
        _ = Dispatcher.BeginInvoke(Close);
    }
    async void CheckUpdate(object sender,RoutedEventArgs e)
    {
        if(working||network.Busy) return;
        if(Updates.Pending) { await ResumeUpdate(); return; }
        if(!network.Connected||!settings.AllTraffic||!settings.KillSwitch||!network.ProtectionArmed)
        { ShowNotice("Для обновления подключите полный туннель с kill switch. Прямая загрузка не используется."); return; }
        using var cancel=new CancellationTokenSource(); updateOperation=cancel; UpdateTransaction? staged=null;
        working=true; UpdateButton.IsEnabled=false; CancelUpdateButton.Visibility=Visibility.Visible;
        try
        {
            UpdateStatus.Text="Проверка подписанного выпуска через VPS…";
            var offer=await Updates.Check(cancel.Token);
            if(offer==null) { UpdateStatus.Text="Новой стабильной версии нет. Если это первый выпуск, он ещё не опубликован в Releases."; return; }
            var notes=offer.Notes.Length>3000?offer.Notes[..3000]+"…":offer.Notes;
            if(MessageBox.Show(this,"Доступна версия "+offer.Manifest.Version+".\n\n"+notes+"\n\nСкачать и установить? Во время замены файлов интернет будет заблокирован. После запуска туннель восстановится автоматически; при ошибке блокировка сохранится.","Обновление Proxy Tunnel",MessageBoxButton.YesNo,MessageBoxImage.Information)!=MessageBoxResult.Yes) { UpdateStatus.Text="Установка отменена."; return; }
            var transaction=await Updates.Stage(offer,message=>Dispatcher.BeginInvoke(()=>UpdateStatus.Text=message),cancel.Token);
            staged=transaction;
            cancel.Token.ThrowIfCancellationRequested();
            UpdateStatus.Text="Пакет проверен. Подготовка отдельного установщика…";
            await Updates.LaunchHelper(transaction);
            CancelUpdateButton.Visibility=Visibility.Collapsed;
            await network.PauseForUpdate(transaction);
            FinishUpdateHandoff();
        }
        catch(OperationCanceledException) { UpdateStatus.Text=cancel.IsCancellationRequested?"Проверка или загрузка отменена; установка не началась.":"Время ожидания истекло; установка не началась."; }
        catch(Exception ex) { UpdateStatus.Text="Обновление не завершено: "+LogPrivacy.Clean(ex.GetBaseException().Message); network.ReportError(ex); RollbackUpdateButton.Visibility=Updates.Pending?Visibility.Visible:Visibility.Collapsed; }
        finally { if(staged!=null&&!closing&&!Updates.Pending) try { File.WriteAllText(System.IO.Path.Combine(Updates.DirectoryFor(staged.Id),"abort"),"abort"); } catch { } updateOperation=null; working=false; UpdateButton.IsEnabled=true; CancelUpdateButton.Visibility=Visibility.Collapsed; }
    }
    void CancelUpdate(object sender,RoutedEventArgs e)=>updateOperation?.Cancel();
    void FinishUpdateHandoff()
    {
        closing=true; clock.Stop(); vpsLogOperation?.Cancel(); copyLogOperation?.Cancel();
        network.Dispose(); tray.Visible=false; tray.Dispose(); Close();
    }
    public async Task ResumeUpdate()
    {
        if(working) return;
        working=true; UpdateButton.IsEnabled=false;
        try
        {
            var transaction=Updates.Read();
            Updates.ValidateRunning();
            if(!string.Equals(System.IO.Path.GetFullPath(transaction.Target),System.IO.Path.GetFullPath(Environment.ProcessPath!),StringComparison.OrdinalIgnoreCase)) throw new IOException("Завершите обновление из исходной папки приложения.");
            ShowNotice("Восстановление после обновления. Прямой интернет остаётся заблокированным.");
            UpdateStatus.Text="Восстанавливаем туннель и проверяем выход через VPS…";
            await network.Connect();
            if(Updates.Pending) { UpdateStatus.Text="Туннель пока не подтверждён. Защита сохраняется; повторите подключение или верните прежнюю версию."; RollbackUpdateButton.Visibility=Visibility.Visible; }
            else { UpdateStatus.Text="Обновление завершено. Туннель работает, kill switch активен."; RollbackUpdateButton.Visibility=Visibility.Collapsed; ShowNotice("Обновление завершено: выход через VPS подтверждён."); }
        }
        catch(Exception ex) { UpdateStatus.Text="Восстановление не завершено: "+LogPrivacy.Clean(ex.GetBaseException().Message); network.ReportError(ex); RollbackUpdateButton.Visibility=Visibility.Visible; }
        finally { working=false; UpdateButton.IsEnabled=true; }
    }
    async void RollbackUpdate(object sender,RoutedEventArgs e)
    {
        if(working||network.Busy) return;
        if(MessageBox.Show(this,"Вернуть резервную копию приложения? Интернет останется заблокированным до восстановления туннеля.","Откат обновления",MessageBoxButton.YesNo)!=MessageBoxResult.Yes) return;
        working=true;
        try { var transaction=Updates.PrepareRollback(); await Updates.LaunchHelper(transaction); await network.PauseForUpdate(transaction); FinishUpdateHandoff(); }
        catch(Exception ex) { UpdateStatus.Text="Откат пока не начат: "+LogPrivacy.Clean(ex.GetBaseException().Message); }
        finally { working=false; }
    }
    public void RenderPages(string directory)
    {
        Directory.CreateDirectory(directory);
        if(TestContext.Enabled) { network.Journal.Add("Проверка интерфейса: потеря связи с сетевым процессом",LogSeverity.Critical,"preview-engine"); network.Journal.Add("Проверка интерфейса: ошибка DNS",LogSeverity.Critical,"preview-dns"); RenderJournal(); }
        foreach(var name in new[]{"overview","services","server","log","settings"})
        {
            ShowPage(name); RenderJournal(); UpdateLayout();
            var content=(FrameworkElement)Content;
            var bitmap=new RenderTargetBitmap((int)content.ActualWidth,(int)content.ActualHeight,96,96,PixelFormats.Pbgra32);
            bitmap.Render(content); var encoder=new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var stream=File.Create(Path.Combine(directory,name+".png")); encoder.Save(stream);
        }
        var previousMode=settings.AllTraffic;
        settings.AllTraffic=false; Update(); ShowPage("overview"); UpdateLayout();
        var selectiveContent=(FrameworkElement)Content;
        var selectiveBitmap=new RenderTargetBitmap((int)selectiveContent.ActualWidth,(int)selectiveContent.ActualHeight,96,96,PixelFormats.Pbgra32);
        selectiveBitmap.Render(selectiveContent); var selectiveEncoder=new PngBitmapEncoder(); selectiveEncoder.Frames.Add(BitmapFrame.Create(selectiveBitmap));
        using(var selectiveFile=File.Create(Path.Combine(directory,"overview-selective.png"))) selectiveEncoder.Save(selectiveFile);
        settings.AllTraffic=previousMode; Update();
        ShowPage("overview");
    }
}
