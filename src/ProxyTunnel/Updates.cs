using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProxyTunnelPrototype;

public sealed record UpdateManifest(string Version,string ArchiveSha256,long ArchiveSize,string ExeSha256);
public sealed record UpdateOffer(UpdateManifest Manifest,byte[] Json,byte[] Signature,string Download,string Notes);
public sealed class UpdateTransaction
{
    public string Id { get; set; }="";
    public string Target { get; set; }="";
    public string OldHash { get; set; }="";
    public string ParentHash { get; set; }="";
    public bool Rollback { get; set; }
    public int ParentId { get; set; }
    public long ParentStart { get; set; }
    public string Step { get; set; }="prepared";
    public string Error { get; set; }="";
}

internal static class Updates
{
    public const string Repository="lonchdev/proxy-tunnel-desktop";
    public const string Asset="ProxyTunnel-update-win-x64.zip";
    public const long MaximumArchive=256L*1024*1024;
    public static string Root=>Path.Combine(Settings.DataDir,"updates");
    static string State=>Path.Combine(Root,"pending.json");
    public static bool Pending=>File.Exists(State);
    public static UpdateTransaction Read()=>JsonSerializer.Deserialize<UpdateTransaction>(File.ReadAllText(State))??throw new IOException("Повреждён журнал обновления; блокировка сохраняется.");
    public static void Save(UpdateTransaction transaction)=>AtomicFile.Write(State,JsonSerializer.Serialize(transaction));
    public static string DirectoryFor(string id)
    {
        if(!Guid.TryParseExact(id,"N",out _)) throw new IOException("Некорректный идентификатор обновления.");
        return Path.Combine(Root,id);
    }
    internal static string Hash(string path) { using var stream=File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
    static string PublicKey
    {
        get { using var stream=typeof(Updates).Assembly.GetManifestResourceStream("update-public-key.pem")!; using var reader=new StreamReader(stream); return reader.ReadToEnd(); }
    }
    public static UpdateManifest Verify(byte[] json,byte[] signature,string? publicKey=null)
    {
        if(json.Length>65536||signature.Length!=64) throw new IOException("Недопустимый формат подписи обновления.");
        using var key=ECDsa.Create(); key.ImportFromPem(publicKey??PublicKey);
        if(!key.VerifyData(json,signature,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new IOException("Подпись обновления не подтверждена. Установка запрещена.");
        var manifest=JsonSerializer.Deserialize<UpdateManifest>(json)??throw new IOException("Пустой манифест.");
        if(!Version.TryParse(manifest.Version,out var version)||version.Major<0||manifest.ArchiveSize<=0||manifest.ArchiveSize>MaximumArchive||!ValidHash(manifest.ArchiveSha256)||!ValidHash(manifest.ExeSha256)) throw new IOException("Некорректные данные обновления.");
        return manifest;
    }
    static bool ValidHash(string text)=>text!=null&&text.Length==64&&text.All(Uri.IsHexDigit);
    static HttpClient Client()
    {
        var client=new HttpClient(new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:"+ConfigBuilder.PortBase),AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
        client.DefaultRequestHeaders.UserAgent.ParseAdd("ProxyTunnel-Desktop/"+typeof(Updates).Assembly.GetName().Version);
        return client;
    }
    internal static bool AllowedUrl(Uri uri)=>uri.Scheme=="https"&&uri.IsDefaultPort&&uri.UserInfo.Length==0&&(uri.Host.Equals("api.github.com",StringComparison.OrdinalIgnoreCase)||uri.Host.Equals("github.com",StringComparison.OrdinalIgnoreCase)&&uri.AbsolutePath.StartsWith("/"+Repository+"/releases/download/",StringComparison.Ordinal)||uri.Host.Equals("release-assets.githubusercontent.com",StringComparison.OrdinalIgnoreCase)||uri.Host.Equals("objects.githubusercontent.com",StringComparison.OrdinalIgnoreCase));
    static async Task<HttpResponseMessage> Request(HttpClient client,string url,CancellationToken token)
    {
        for(int i=0;i<6;i++)
        {
            var uri=new Uri(url); if(!AllowedUrl(uri)) throw new IOException("Недопустимый адрес обновления.");
            var response=await client.GetAsync(uri,HttpCompletionOption.ResponseHeadersRead,token);
            if((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            { var next=response.Headers.Location; response.Dispose(); if(next==null) throw new IOException("Пустое перенаправление."); url=new Uri(uri,next).AbsoluteUri; continue; }
            return response;
        }
        throw new IOException("Слишком много перенаправлений загрузки.");
    }
    static async Task<byte[]> Bytes(HttpClient client,string url,int limit,CancellationToken token)
    {
        using var response=await Request(client,url,token); response.EnsureSuccessStatusCode();
        using var output=new MemoryStream(); using var input=await response.Content.ReadAsStreamAsync(token); var buffer=new byte[8192];
        int count; while((count=await input.ReadAsync(buffer,token))>0) { if(output.Length+count>limit) throw new IOException("Ответ сервера превышает ограничение."); output.Write(buffer,0,count); }
        return output.ToArray();
    }
    public static async Task<UpdateOffer?> Check(CancellationToken token)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(45));
        using var client=Client(); using var response=await Request(client,"https://api.github.com/repos/"+Repository+"/releases/latest",timeout.Token);
        if(response.StatusCode==HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        using var input=await response.Content.ReadAsStreamAsync(timeout.Token); using var data=new MemoryStream(); var buffer=new byte[8192]; int count;
        while((count=await input.ReadAsync(buffer,timeout.Token))>0) { if(data.Length+count>1024*1024) throw new IOException("Ответ GitHub слишком большой."); data.Write(buffer,0,count); }
        using var document=JsonDocument.Parse(data.ToArray()); var release=document.RootElement;
        if(release.GetProperty("draft").GetBoolean()||release.GetProperty("prerelease").GetBoolean()) return null;
        var tag=release.GetProperty("tag_name").GetString()??"";
        if(!Version.TryParse(tag.TrimStart('v'),out var published)) throw new IOException("Неподдерживаемый номер выпуска.");
        if(published<=typeof(Updates).Assembly.GetName().Version) return null;
        string Url(string name)
        {
            var found=release.GetProperty("assets").EnumerateArray().Where(a=>a.GetProperty("name").GetString()==name).ToArray();
            if(found.Length!=1) throw new IOException("В выпуске отсутствует единственный файл "+name);
            var url=found[0].GetProperty("browser_download_url").GetString()!;
            if(!url.StartsWith("https://github.com/"+Repository+"/releases/download/",StringComparison.Ordinal)) throw new IOException("Файл находится за пределами репозитория.");
            return url;
        }
        var json=await Bytes(client,Url("update.json"),65536,timeout.Token);
        var signature=await Bytes(client,Url("update.sig"),64,timeout.Token);
        var manifest=Verify(json,signature);
        if(Version.Parse(manifest.Version)!=published) throw new IOException("Подписанная версия не соответствует выпуску GitHub.");
        return new(manifest,json,signature,Url(Asset),release.TryGetProperty("body",out var notes)?notes.GetString()??"":"");
    }
    public static async Task<UpdateTransaction> Stage(UpdateOffer offer,Action<string> status,CancellationToken token)
    {
        if(Pending) throw new IOException("Сначала завершите предыдущее обновление.");
        var target=Environment.ProcessPath!;
        if(!Path.GetFileName(target).Equals("ProxyTunnel-Prototype.exe",StringComparison.OrdinalIgnoreCase)) throw new IOException("Обновление поддерживается в готовой EXE-сборке.");
        var transaction=new UpdateTransaction{Id=Guid.NewGuid().ToString("N"),Target=Path.GetFullPath(target),OldHash=Hash(target),ParentHash=Hash(target),ParentId=Environment.ProcessId,ParentStart=Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks};
        var folder=DirectoryFor(transaction.Id); Directory.CreateDirectory(folder);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromMinutes(15));
        try
        {
            using var client=Client(); using var response=await Request(client,offer.Download,timeout.Token); response.EnsureSuccessStatusCode();
            var archive=Path.Combine(folder,"download.zip");
            using(var output=new FileStream(archive,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            using(var input=await response.Content.ReadAsStreamAsync(timeout.Token))
            {
                var buffer=new byte[65536]; int count; long total=0,reported=-1;
                while((count=await input.ReadAsync(buffer,timeout.Token))>0)
                { total+=count; if(total>offer.Manifest.ArchiveSize) throw new IOException("Размер архива не совпадает с подписанным."); await output.WriteAsync(buffer.AsMemory(0,count),timeout.Token); var percent=total*100/offer.Manifest.ArchiveSize; if(percent!=reported) { reported=percent; status("Скачивание через VPS: "+percent+"%"); } }
                if(total!=offer.Manifest.ArchiveSize) throw new IOException("Архив скачан не полностью.");
                output.Flush(true);
            }
            await File.WriteAllBytesAsync(Path.Combine(folder,"update.json"),offer.Json,token);
            await File.WriteAllBytesAsync(Path.Combine(folder,"update.sig"),offer.Signature,token);
            ExtractVerified(folder,offer.Manifest);
            File.Copy(target,Path.Combine(folder,"updater.exe"));
            if(Hash(Path.Combine(folder,"updater.exe"))!=transaction.OldHash) throw new IOException("Не удалось проверить копию установщика.");
            AtomicFile.Write(Path.Combine(folder,"transaction.json"),JsonSerializer.Serialize(transaction));
            return transaction;
        }
        catch { CleanupFolder(folder); throw; }
    }
    internal static void ExtractVerified(string folder,UpdateManifest manifest)
    {
        var archive=Path.Combine(folder,"download.zip");
        if(new FileInfo(archive).Length!=manifest.ArchiveSize||!Hash(archive).Equals(manifest.ArchiveSha256,StringComparison.OrdinalIgnoreCase)) throw new IOException("Контрольная сумма архива не совпадает.");
        using var zip=ZipFile.OpenRead(archive);
        if(zip.Entries.Count!=1||zip.Entries[0].FullName!="ProxyTunnel-Prototype.exe"||zip.Entries[0].Length>512L*1024*1024||zip.Entries[0].Length<1) throw new IOException("Недопустимый состав ZIP. Требуется только ProxyTunnel-Prototype.exe.");
        var path=Path.Combine(folder,"new.exe"); zip.Entries[0].ExtractToFile(path,true);
        if(!Hash(path).Equals(manifest.ExeSha256,StringComparison.OrdinalIgnoreCase)) { File.Delete(path); throw new IOException("Контрольная сумма EXE не совпадает."); }
    }
    internal static void CleanupFolder(string folder)
    {
        // Never recursively delete a supplied path.
        foreach(var name in new[]{"download.zip","new.exe","updater.exe","update.json","update.sig","transaction.json","ready"}) try { File.Delete(Path.Combine(folder,name)); } catch(IOException) { }
    }
    public static async Task LaunchHelper(UpdateTransaction transaction)
    {
        var folder=DirectoryFor(transaction.Id);
        var start=new ProcessStartInfo(Path.Combine(folder,"updater.exe")){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=folder};
        start.ArgumentList.Add("--apply-update"); start.ArgumentList.Add(transaction.Id);
        foreach(var key in new[]{"PROXY_TUNNEL_TEST_DATA","PROXY_TUNNEL_TEST_PORT_BASE","PROXY_TUNNEL_TEST_PROXY_STORE"}) start.Environment.Remove(key);
        using var helper=Process.Start(start)??throw new IOException("Установщик не запущен.");
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while(!File.Exists(Path.Combine(folder,"ready"))) { if(helper.HasExited) throw new IOException("Установщик завершился до начала обновления."); await Task.Delay(100,timeout.Token); }
    }
    public static UpdateTransaction PrepareRollback()
    {
        var transaction=Read(); var folder=DirectoryFor(transaction.Id);
        if(!File.Exists(Path.Combine(folder,"installer.done"))) throw new IOException("Установщик ещё проверяет запуск. Повторите откат после завершения проверки (до 3 минут).");
        if(!Hash(Path.Combine(folder,"previous.exe")).Equals(transaction.OldHash,StringComparison.OrdinalIgnoreCase)) throw new IOException("Резервная копия не прошла проверку.");
        transaction.ParentId=Environment.ProcessId; transaction.ParentStart=Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks;
        transaction.ParentHash=Hash(Environment.ProcessPath!); transaction.Rollback=true; transaction.Step="prepared";
        File.Copy(Environment.ProcessPath!,Path.Combine(folder,"updater.exe"),true);
        File.Delete(Path.Combine(folder,"ready")); File.Delete(Path.Combine(folder,"installer.done"));
        AtomicFile.Write(Path.Combine(folder,"transaction.json"),JsonSerializer.Serialize(transaction)); return transaction;
    }
    public static void Complete()
    {
        if(!Pending) return;
        var transaction=Read(); transaction.Step="complete"; Save(transaction);
        AtomicFile.Write(Path.Combine(DirectoryFor(transaction.Id),"complete"),"verified");
        File.Delete(State);
    }
    public static void CancelRecovery() { if(Pending) File.Delete(State); }
    public static void ValidateRunning()
    {
        var transaction=Read(); var folder=DirectoryFor(transaction.Id);
        var manifest=Verify(File.ReadAllBytes(Path.Combine(folder,"update.json")),File.ReadAllBytes(Path.Combine(folder,"update.sig")));
        var actual=Hash(Environment.ProcessPath!);
        if(!actual.Equals(transaction.OldHash,StringComparison.OrdinalIgnoreCase)&&!actual.Equals(manifest.ExeSha256,StringComparison.OrdinalIgnoreCase)) throw new IOException("Запущенный EXE не соответствует ни проверенному обновлению, ни резервной версии.");
    }
}
