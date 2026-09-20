param(
    [Parameter(Mandatory)][ValidateSet('net462', 'net472', 'net481', 'net6.0', 'net8.0')][string]$Framework,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug',
    [string]$DotNetPath = 'dotnet',
    [switch]$NoRestore
)
$ErrorActionPreference = 'Stop'
$testRepository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$testResults = Join-Path $testRepository "artifacts/test-results/$Framework"
New-Item -ItemType Directory -Force -Path $testResults | Out-Null
if ($Framework.StartsWith('net4') -and -not $IsWindows) { throw '.NET Framework execution requires Windows.' }
$testProjects = @('pki-test', 'library-core-tests', 'etee-crypto-tests', 'services-tests', 'compatibility-tests')
if ($Framework -eq 'net6.0' -or $Framework -eq 'net8.0') { $testProjects += 'performance-tests' }
Push-Location $testRepository
try {
    if (-not $NoRestore) {
        & $DotNetPath restore ehi.sln --source https://api.nuget.org/v3/index.json
        if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }
    }
    $testFailures = @()
    foreach ($testProject in $testProjects) {
        & $DotNetPath test "$testProject/$testProject.csproj" -f $Framework -c $Configuration --no-restore -p:SignAssembly=false --results-directory $testResults --logger "trx;LogFileName=$testProject.trx" --logger 'console;verbosity=minimal'
        if ($LASTEXITCODE -ne 0) { $testFailures += $testProject }
    }
    if ($testFailures.Count) { throw "Failed test projects: $($testFailures -join ', ')" }
}
finally { Pop-Location }
