$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$toolRoot = Join-Path (Split-Path $projectRoot -Parent) 'tools'
New-Item -ItemType Directory -Force $toolRoot | Out-Null
$version = '1.14.4'
$downloads = @(
  @{ Name="singbox.zip"; Url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip"; Hash='99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df' },
  @{ Name="singbox-linux.tar.gz"; Url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-linux-amd64.tar.gz"; Hash='699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968' }
)
foreach ($download in $downloads) {
  $target = Join-Path $toolRoot $download.Name
  if (!(Test-Path -LiteralPath $target)) { Invoke-WebRequest -UseBasicParsing $download.Url -OutFile $target }
  if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $download.Hash) { throw "Checksum mismatch: $target" }
}
Expand-Archive -LiteralPath (Join-Path $toolRoot 'singbox.zip') -DestinationPath (Join-Path $toolRoot 'singbox') -Force
$sdkPath = Join-Path $toolRoot 'dotnet/dotnet.exe'
if (!(Test-Path -LiteralPath $sdkPath)) {
  if (Get-Command dotnet -ErrorAction SilentlyContinue) { $sdkPath = (Get-Command dotnet).Source }
  else { throw 'Install the official .NET 8 SDK from https://dotnet.microsoft.com/download/dotnet/8.0' }
}
$env:DOTNET_CLI_HOME = Join-Path $toolRoot 'dotnet-home'
$env:NUGET_PACKAGES = Join-Path $toolRoot 'nuget'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
& $sdkPath publish (Join-Path $projectRoot 'ProxyTunnelPrototype.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false "-p:RestoreConfigFile=$projectRoot/NuGet.Config" -o (Join-Path $projectRoot 'publish')
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
