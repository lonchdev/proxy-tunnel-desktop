using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

if(args.Length==3&&args[0]=="keygen")
{
    if(File.Exists(args[1])||File.Exists(args[2])) throw new IOException("Refusing to overwrite an existing signing key.");
    using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    File.WriteAllText(args[1],key.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(args[2],key.ExportSubjectPublicKeyInfoPem());
    Console.WriteLine("Private key saved separately; public verification key created."); return;
}
if(args.Length==3&&args[0]=="verify")
{
    var verifyFolder=Path.GetFullPath(args[1]);
    using var key=ECDsa.Create(); key.ImportFromPem(File.ReadAllText(args[2]));
    var json=File.ReadAllBytes(Path.Combine(verifyFolder,"update.json"));
    if(!key.VerifyData(json,File.ReadAllBytes(Path.Combine(verifyFolder,"update.sig")),HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new IOException("Invalid signature.");
    using var document=JsonDocument.Parse(json); var verifyManifest=document.RootElement;
    var zipPath=Path.Combine(verifyFolder,"ProxyTunnel-update-win-x64.zip");
    using var data=File.OpenRead(zipPath);
    if(Convert.ToHexString(SHA256.HashData(data))!=verifyManifest.GetProperty("ArchiveSha256").GetString()||data.Length!=verifyManifest.GetProperty("ArchiveSize").GetInt64()) throw new IOException("Archive mismatch.");
    using var zip=ZipFile.OpenRead(zipPath);
    if(zip.Entries.Count!=1||zip.Entries[0].FullName!="ProxyTunnel-Prototype.exe") throw new IOException("Invalid package layout.");
    using var exe=zip.Entries[0].Open();
    if(Convert.ToHexString(SHA256.HashData(exe))!=verifyManifest.GetProperty("ExeSha256").GetString()) throw new IOException("EXE mismatch.");
    Console.WriteLine("Signature, archive, and embedded EXE verified."); return;
}
if(args.Length!=5||args[0]!="package") throw new ArgumentException("keygen PRIVATE_PATH PUBLIC_PATH | package EXE VERSION PRIVATE_KEY OUTPUT_FOLDER");
var executable=Path.GetFullPath(args[1]); var version=Version.Parse(args[2]);
Version Full(Version v)=>new(v.Major,v.Minor,Math.Max(0,v.Build),Math.Max(0,v.Revision));
if(Full(Version.Parse(System.Diagnostics.FileVersionInfo.GetVersionInfo(executable).ProductVersion!.Split('+')[0]))!=Full(version)) throw new IOException("Version does not match EXE.");
Directory.CreateDirectory(args[4]); var folder=Path.GetFullPath(args[4]);
var archive=Path.Combine(folder,"ProxyTunnel-update-win-x64.zip");
if(File.Exists(archive)) throw new IOException("Output archive already exists; use a new output folder.");
using(var zip=ZipFile.Open(archive,ZipArchiveMode.Create)) zip.CreateEntryFromFile(executable,"ProxyTunnel-Prototype.exe",CompressionLevel.Optimal);
string Hash(string path) { using var input=File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(input)); }
var manifest=JsonSerializer.SerializeToUtf8Bytes(new {Version=version.ToString(),ArchiveSha256=Hash(archive),ArchiveSize=new FileInfo(archive).Length,ExeSha256=Hash(executable)});
using var signingKey=ECDsa.Create(); signingKey.ImportFromPem(File.ReadAllText(args[3]));
File.WriteAllBytes(Path.Combine(folder,"update.json"),manifest);
File.WriteAllBytes(Path.Combine(folder,"update.sig"),signingKey.SignData(manifest,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
Console.WriteLine("Signed update package created. Private key was not copied.");
