param(
    [ValidateSet('all', 'crypto', 'memory', 'http')][string]$Suite = 'all',
    [switch]$Quick,
    [switch]$DisableTiering
)
$ErrorActionPreference = 'Stop'
$profileRepo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profileOutput = Join-Path $profileRepo 'artifacts\profiling'
New-Item -ItemType Directory -Force -Path $profileOutput | Out-Null
$profileCommit = git -C $profileRepo rev-parse HEAD
$profileName = if ($DisableTiering) { 'linux-1cpu-1g-no-tiering' } else { 'linux-1cpu-1g' }
$profileArguments = '--suite ' + $Suite + ' --output /out/' + $profileName + '.json'
if ($Quick) { $profileArguments += ' --quick' }
$profileCommand = 'cp -a /src /tmp/eHI && cd /tmp/eHI && dotnet build benchmarks/benchmarks.csproj -c Release -p:SignAssembly=false --source https://api.nuget.org/v3/index.json -v quiet > /out/' + $profileName + '-build.log 2>&1 && dotnet benchmarks/bin/Release/net10.0/benchmarks.dll ' + $profileArguments + ' > /out/' + $profileName + '.log 2>&1'
$profileDockerArguments = @('run', '--rm', '--cpus', '1', '--memory', '1g', '-e', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '-e', "PROFILE_COMMIT=$profileCommit", '-v', "${profileRepo}:/src:ro", '-v', "${profileOutput}:/out")
if ($DisableTiering) { $profileDockerArguments += @('-e', 'DOTNET_TieredCompilation=0') }
$profileDockerArguments += @('mcr.microsoft.com/dotnet/sdk:10.0@sha256:2fa828c68761b1b8c23d7662dc134421b9d3b59fe1425fdbc80804e390cdb24d', 'bash', '-lc', $profileCommand)
& docker @profileDockerArguments
if ($LASTEXITCODE -ne 0) { throw "Profiling failed; inspect $profileOutput" }
Write-Output "Results: $(Join-Path $profileOutput ($profileName + '.json'))"
