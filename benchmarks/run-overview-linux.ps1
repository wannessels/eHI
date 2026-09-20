$ErrorActionPreference = 'Stop'
# The fourteen full profiles used by the performance overview: one build, fresh processes.
$profileRepo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profileOutput = Join-Path $profileRepo 'artifacts/profiling'
New-Item -ItemType Directory -Path $profileOutput -Force | Out-Null
$profileCommit = git -C $profileRepo rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot determine the source commit' }
$profileCases = @(
    'pharmacy-c4-native-custom|--suite pharmacy --concurrency 4 --requests 64 --backend native --trust custom',
    'pharmacy-c8-native-custom|--suite pharmacy --concurrency 8 --requests 128 --backend native --trust custom',
    'pharmacy-c4-bc-custom|--suite pharmacy --concurrency 4 --requests 64 --backend bouncycastle --trust custom',
    'pharmacy-c8-bc-custom|--suite pharmacy --concurrency 8 --requests 128 --backend bouncycastle --trust custom',
    'crypto-32kib-c4-tdefault|--suite crypto-concurrency --payload-kib 32 --concurrency 4 --requests 256 --threshold-mib -1',
    'crypto-32kib-c8-tdefault|--suite crypto-concurrency --payload-kib 32 --concurrency 8 --requests 256 --threshold-mib -1',
    'crypto-8192kib-c4-tdefault|--suite crypto-concurrency --payload-kib 8192 --concurrency 4 --requests 32 --threshold-mib -1',
    'crypto-32768kib-c4-tdefault|--suite crypto-concurrency --payload-kib 32768 --concurrency 4 --requests 16 --threshold-mib -1',
    'crypto-32768kib-c4-t64|--suite crypto-concurrency --payload-kib 32768 --concurrency 4 --requests 16 --threshold-mib 64',
    'keys|--suite keys',
    'soap|--suite soap',
    'pharmacy-c4-native-system|--suite pharmacy --concurrency 4 --requests 64 --backend native --trust system',
    'pharmacy-c8-native-system|--suite pharmacy --concurrency 8 --requests 128 --backend native --trust system',
    'pharmacy-c4-bc-system|--suite pharmacy --concurrency 4 --requests 64 --backend bouncycastle --trust system'
)
$profileCommand = 'set -e; cp -a /src /tmp/eHI; cd /tmp/eHI; dotnet build benchmarks/benchmarks.csproj -c Release -p:SignAssembly=false --source https://api.nuget.org/v3/index.json -v quiet > /out/rebench-build.log 2>&1; failed=0; '
foreach ($profileCase in $profileCases) {
    $profileName, $profileArguments = $profileCase.Split('|')
    $profileFile = "rebench-$profileName-net8-4cpu-16g"
    $profileCommand += "echo START $profileName `$(date -u +%FT%TZ); if ! dotnet benchmarks/bin/Release/net8.0/benchmarks.dll $profileArguments --output /out/$profileFile.json > /out/$profileFile.log 2>&1; then echo FAILED $profileName; failed=1; fi; echo END $profileName `$(date -u +%FT%TZ); "
}
$profileCommand += 'exit "$failed"'
$profileDockerArguments = @('run', '--rm', '--cpus', '4', '--memory', '16g', '-e', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '-e', "PROFILE_COMMIT=$profileCommit", '-v', "${profileRepo}:/src:ro", '-v', "${profileOutput}:/out",
    'mcr.microsoft.com/dotnet/sdk@sha256:78235e09001f52b6592c458ac010775ebac6725422e80cd0c1650590f67b2743', 'bash', '-lc', $profileCommand)
Write-Output "Source commit: $profileCommit; container limits: 4 CPUs / 16 GiB"
& docker @profileDockerArguments
if ($LASTEXITCODE -ne 0) { throw "A benchmark failed; inspect $profileOutput" }
Write-Output "All fourteen profiles completed. Results: $profileOutput"
