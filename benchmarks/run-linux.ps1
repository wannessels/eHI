param(
    [ValidateSet('all', 'crypto', 'memory', 'http', 'native-memory', 'crypto-concurrency', 'pharmacy', 'keys', 'soap')][string]$Suite = 'all',
    [ValidateRange(1, 1024)][int]$PayloadMiB = 8,
    [ValidateRange(1, 1048576)][int]$PayloadKiB = 8192,
    [ValidateRange(1, 64)][int]$Concurrency = 4,
    [ValidateRange(1, 10000)][int]$Requests = 32,
    [ValidateRange(1, 16)][int]$CpuLimit = 1,
    [ValidateRange(1, 64)][int]$MemoryGiB = 1,
    [ValidateRange(-1, 4096)][int]$ThresholdMiB = -1,
    [ValidateRange(1, 1024)][int]$Prescribers = 16,
    [ValidateRange(0, 10000000)][int]$CitizenCrlEntries = 350000,
    [ValidateRange(0, 10000000)][int]$EHealthCrlEntries = 20000,
    [ValidateSet('native', 'bouncycastle')][string]$Backend = 'native',
    [ValidateSet('custom', 'system')][string]$Trust = 'custom',
    [switch]$Quick,
    [switch]$ServerGC,
    [switch]$DisableTiering
)
$ErrorActionPreference = 'Stop'
$profileRepo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profileOutput = Join-Path $profileRepo 'artifacts\profiling'
New-Item -ItemType Directory -Force -Path $profileOutput | Out-Null
$profileCommit = git -C $profileRepo rev-parse HEAD
$profileName = "backends-net8-$($CpuLimit)cpu-$($MemoryGiB)g" + $(if ($DisableTiering) { '-no-tiering' } else { '' })
if ($Suite -eq 'native-memory') { $profileName = "native-streaming-$($PayloadMiB)mib-t$ThresholdMiB-net8-$($CpuLimit)cpu-$($MemoryGiB)g" + $(if ($DisableTiering) { '-no-tiering' } else { '' }) }
if ($Suite -eq 'crypto-concurrency') { $profileName = "crypto-$($PayloadKiB)kib-c$Concurrency-t$(if ($ThresholdMiB -lt 0) { 'default' } else { $ThresholdMiB })-net8-$($CpuLimit)cpu-$($MemoryGiB)g" + $(if ($DisableTiering) { '-no-tiering' } else { '' }) }
if ($Suite -eq 'keys') { $profileName = "keys-net8-$($CpuLimit)cpu-$($MemoryGiB)g" }
if ($Suite -eq 'soap') { $profileName = "soap-net8-$($CpuLimit)cpu-$($MemoryGiB)g" }
if ($Suite -eq 'pharmacy') { $profileName = "pharmacy-c$Concurrency-p$Prescribers-crl$CitizenCrlEntries$(if ($Backend -eq 'bouncycastle') { '-bc' } else { '' })$(if ($Trust -eq 'system') { '-systrust' } else { '' })-net8-$($CpuLimit)cpu-$($MemoryGiB)g" + $(if ($DisableTiering) { '-no-tiering' } else { '' }) }
if ($ServerGC) { $profileName += '-server' }
$profileArguments = '--suite ' + $Suite + ' --output /out/' + $profileName + '.json'
if ($Suite -eq 'native-memory') { $profileArguments += " --payload-mib $PayloadMiB --threshold-mib $ThresholdMiB" }
if ($Suite -eq 'crypto-concurrency') { $profileArguments += " --payload-kib $PayloadKiB --concurrency $Concurrency --requests $Requests --threshold-mib $ThresholdMiB" }
if ($Suite -eq 'pharmacy') { $profileArguments += " --concurrency $Concurrency --requests $Requests --prescribers $Prescribers --citizen-crl-entries $CitizenCrlEntries --ehealth-crl-entries $EHealthCrlEntries --backend $Backend --trust $Trust" }
if ($Quick) { $profileArguments += ' --quick' }
$profileCommand = 'cp -a /src /tmp/eHI && cd /tmp/eHI && dotnet build benchmarks/benchmarks.csproj -c Release -p:SignAssembly=false --source https://api.nuget.org/v3/index.json -v quiet > /out/' + $profileName + '-build.log 2>&1 && dotnet benchmarks/bin/Release/net8.0/benchmarks.dll ' + $profileArguments + ' > /out/' + $profileName + '.log 2>&1'
$profileDockerArguments = @('run', '--rm', '--cpus', "$CpuLimit", '--memory', "$($MemoryGiB)g", '-e', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '-e', "PROFILE_COMMIT=$profileCommit", '-v', "${profileRepo}:/src:ro", '-v', "${profileOutput}:/out")
if ($DisableTiering) { $profileDockerArguments += @('-e', 'DOTNET_TieredCompilation=0') }
if ($ServerGC) { $profileDockerArguments += @('-e', 'DOTNET_gcServer=1') }
$profileDockerArguments += @('mcr.microsoft.com/dotnet/sdk@sha256:78235e09001f52b6592c458ac010775ebac6725422e80cd0c1650590f67b2743', 'bash', '-lc', $profileCommand)
& docker @profileDockerArguments
if ($LASTEXITCODE -ne 0) { throw "Profiling failed; inspect $profileOutput" }
Write-Output "Results: $(Join-Path $profileOutput ($profileName + '.json'))"
