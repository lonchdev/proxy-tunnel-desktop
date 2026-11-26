using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProxyTunnelPrototype;

internal static class UpdateTests
{
    public static int Run()
    {
        var lines=new List<string>();
        void Check(bool value,string label) { if(!value) throw new Exception(label); lines.Add("PASS: "+label); }
        bool Reject(Action action) { try { action(); return false; } catch(IOException) { return true; } }
        try
        {
            using var signer=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var root=Path.Combine(Settings.DataDir,"fixture"); Directory.CreateDirectory(root);
            var archive=Path.Combine(root,"download.zip"); var payload=Encoding.UTF8.GetBytes("fixture new binary");
            void Zip(string name)
            {
                if(File.Exists(archive)) File.Delete(archive);
                using var zip=ZipFile.Open(archive,ZipArchiveMode.Create); using var stream=zip.CreateEntry(name).Open(); stream.Write(payload);
            }
            Zip("ProxyTunnel-Prototype.exe");
            UpdateManifest Manifest()=>new("0.1.11",Updates.Hash(archive),new FileInfo(archive).Length,Convert.ToHexString(SHA256.HashData(payload)));
            var manifest=Manifest(); var json=JsonSerializer.SerializeToUtf8Bytes(manifest);
            byte[] Sign(byte[] data)=>signer.SignData(data,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var signature=Sign(json); var publicKey=signer.ExportSubjectPublicKeyInfoPem();
            Check(Updates.Verify(json,signature,publicKey)==manifest,"Pinned-key signature accepts the original manifest");
            var changed=json.ToArray(); changed[5]^=1;
            Check(Reject(()=>Updates.Verify(changed,signature,publicKey)),"Manifest tampering is rejected before parsing or installation");
            using var wrong=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Check(Reject(()=>Updates.Verify(json,signature,wrong.ExportSubjectPublicKeyInfoPem())),"A different signing key is rejected");
            Check(Reject(()=>Updates.Verify(json,new byte[63],publicKey)),"Malformed signature length is rejected");
            var oversized=JsonSerializer.SerializeToUtf8Bytes(manifest with {ArchiveSize=Updates.MaximumArchive+1});
            Check(Reject(()=>Updates.Verify(oversized,Sign(oversized),publicKey)),"Even a signed oversized archive is refused");
            Updates.ExtractVerified(root,manifest);
            Check(File.ReadAllBytes(Path.Combine(root,"new.exe")).SequenceEqual(payload),"Verified single-file archive extracts without changing its payload");
            File.AppendAllText(archive,"tamper");
            Check(Reject(()=>Updates.ExtractVerified(root,manifest)),"Changed archive bytes are rejected");
            Zip("../outside.exe"); manifest=Manifest();
            Check(Reject(()=>Updates.ExtractVerified(root,manifest))&&!File.Exists(Path.Combine(Settings.DataDir,"outside.exe")),"ZIP traversal cannot write outside staging");
            Zip("ProxyTunnel-Prototype.exe"); manifest=Manifest();
            Check(Reject(()=>Updates.ExtractVerified(root,manifest with {ExeSha256=new string('0',64)})),"An EXE checksum mismatch is refused");
            Updates.ExtractVerified(root,manifest);
            var target=Path.Combine(root,"target.exe"); var backup=Path.Combine(root,"previous.exe");
            File.WriteAllText(target,"old binary"); var old=Updates.Hash(target);
            UpdateInstaller.Replace(target,Path.Combine(root,"new.exe"),backup,manifest.ExeSha256,old);
            Check(Updates.Hash(target)==manifest.ExeSha256&&Updates.Hash(backup)==old,"File transaction installs the verified binary and preserves the original backup");
            UpdateInstaller.Rollback(target,backup,old);
            Check(Updates.Hash(target)==old,"Rollback restores the exact original binary");
            File.WriteAllText(backup,"corrupted");
            Check(Reject(()=>UpdateInstaller.Rollback(target,backup,old))&&Updates.Hash(target)==old,"Corrupt backup cannot overwrite the current executable");
            Check(Reject(()=>UpdateInstaller.Replace(target,Path.Combine(root,"new.exe"),backup,new string('0',64),old))&&Updates.Hash(target)==old,"Unverified payload never changes the destination");
            var lockedTarget=Path.Combine(root,"locked.exe"); File.WriteAllText(lockedTarget,"old binary");
            Task retry;
            using(var locked=new FileStream(lockedTarget,FileMode.Open,FileAccess.Read,FileShare.None))
            {
                retry=Task.Run(()=>UpdateInstaller.WhenUnlocked(()=>UpdateInstaller.Replace(lockedTarget,Path.Combine(root,"new.exe"),Path.Combine(root,"locked-backup.exe"),manifest.ExeSha256,old)));
                Thread.Sleep(350);
            }
            retry.GetAwaiter().GetResult();
            Check(Updates.Hash(lockedTarget)==manifest.ExeSha256,"Temporary file locks from the old watchdog are retried before failing installation");
            var strict=KillSwitch.UpdatePlan();
            Check(KillSwitch.UpdateLayers(false).Concat(KillSwitch.UpdateLayers(true)).Distinct().Count()==4,"Update policy covers both connect and receive/accept ALE layers for IPv4 and IPv6");
            Check(!KillSwitch.Simulate(strict,"192.168.1.2","203.0.113.10",24443,6,true)&&!KillSwitch.Simulate(strict,"192.168.1.2","1.1.1.1",443,6,false),"Install policy blocks both VPS transport and other public IPv4");
            Check(!KillSwitch.Simulate(strict,"fd00::1","2606:4700:4700::1111",443,17,true)&&!KillSwitch.Simulate(strict,"192.168.1.2","192.168.1.1",53,17,false),"Install policy blocks public IPv6 and physical LAN/DNS");
            Check(KillSwitch.Simulate(strict,"127.0.0.1","127.0.0.1",12345,6,false),"Only local loopback IPC remains available during installation");
            var recovery=KillSwitch.UpdatePlan(new Settings{Host="203.0.113.10",ServerPort=24443});
            Check(KillSwitch.Simulate(recovery,"192.168.1.2","203.0.113.10",24443,6,true)&&!KillSwitch.Simulate(recovery,"192.168.1.2","1.1.1.1",443,6,true)&&!KillSwitch.Simulate(recovery,"192.168.1.2","203.0.113.10",22,6,false),"Recovery permits the VPS transport but neither broad engine internet access nor SSH");
            Check(!Updates.AllowedUrl(new Uri("http://github.com/"))&&!Updates.AllowedUrl(new Uri("https://github.com.evil.example/"))&&!Updates.AllowedUrl(new Uri("https://github.com/another/repo/releases/download/v1/a.zip")),"HTTP and off-repository download origins are refused");
            Check(Updates.AllowedUrl(new Uri("https://github.com/"+Updates.Repository+"/releases/download/v0.1.11/"+Updates.Asset)),"Expected repository release URL is allowed");
            Check(Reject(()=>Updates.DirectoryFor("../escape")),"Transaction identifiers cannot escape the updates directory");
            KillSwitch.ArmUpdateBlock();
            Check(KillSwitch.Armed,"Isolated guard fixture remains armed across an installation failure");
            KillSwitch.Disarm();
            return 0;
        }
        catch(Exception ex) { lines.Add("FAILED: "+ex); return 1; }
        finally { File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"update-test.txt"),lines); }
    }
}
