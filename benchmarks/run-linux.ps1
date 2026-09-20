param(
    [ValidateSet('all', 'crypto', 'memory', 'http', 'native-memory')][string]$Suite = 'all',
    [ValidateRange(1, 1024)][int]$PayloadMiB = 8,
    [switch]$Quick,
    [switch]$DisableTiering
)
$ErrorActionPreference = 'Stop'
$profileRepo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profileOutput = Join-Path $profileRepo 'artifacts\profiling'
New-Item -ItemType Directory -Force -Path $profileOutput | Out-Null
$profileCommit = git -C $profileRepo rev-parse HEAD
$profileName = if ($DisableTiering) { 'backends-net8-1cpu-1g-no-tiering' } else { 'backends-net8-1cpu-1g' }
if ($Suite -eq 'native-memory') { $profileName = "native-streaming-$($PayloadMiB)mib-net8-1cpu-1g" + $(if ($DisableTiering) { '-no-tiering' } else { '' }) }
$profileArguments = '--suite ' + $Suite + ' --output /out/' + $profileName + '.json'
if ($Suite -eq 'native-memory') { $profileArguments += ' --payload-mib ' + $PayloadMiB }
if ($Quick) { $profileArguments += ' --quick' }
$profileCommand = 'cp -a /src /tmp/eHI && cd /tmp/eHI && dotnet build benchmarks/benchmarks.csproj -c Release -p:SignAssembly=false --source https://api.nuget.org/v3/index.json -v quiet > /out/' + $profileName + '-build.log 2>&1 && dotnet benchmarks/bin/Release/net8.0/benchmarks.dll ' + $profileArguments + ' > /out/' + $profileName + '.log 2>&1'
$profileDockerArguments = @('run', '--rm', '--cpus', '1', '--memory', '1g', '-e', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '-e', "PROFILE_COMMIT=$profileCommit", '-v', "${profileRepo}:/src:ro", '-v', "${profileOutput}:/out")
if ($DisableTiering) { $profileDockerArguments += @('-e', 'DOTNET_TieredCompilation=0') }
$profileDockerArguments += @('mcr.microsoft.com/dotnet/sdk@sha256:78235e09001f52b6592c458ac010775ebac6725422e80cd0c1650590f67b2743', 'bash', '-lc', $profileCommand)
& docker @profileDockerArguments
if ($LASTEXITCODE -ne 0) { throw "Profiling failed; inspect $profileOutput" }
Write-Output "Results: $(Join-Path $profileOutput ($profileName + '.json'))"
