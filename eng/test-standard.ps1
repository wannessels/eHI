param([string]$DotNetPath = 'dotnet')
$ErrorActionPreference = 'Stop'
$standardRepository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$standardFeed = Join-Path $standardRepository 'artifacts/standard-packages'
$standardResults = Join-Path $standardRepository 'artifacts/test-results/netstandard2.0'
$standardVersion = '3.0.0-ci-standard.' + [DateTime]::UtcNow.Ticks
New-Item -ItemType Directory -Force -Path $standardFeed, $standardResults | Out-Null
$standardConfig = Join-Path $standardFeed 'NuGet.Config'
$standardWriter = [System.Xml.XmlWriter]::Create($standardConfig)
try {
    $standardWriter.WriteStartElement('configuration')
    $standardWriter.WriteStartElement('packageSources')
    $standardWriter.WriteElementString('clear', '')
    foreach ($standardSource in @(@('local', $standardFeed), @('nuget.org', 'https://api.nuget.org/v3/index.json'))) {
        $standardWriter.WriteStartElement('add')
        $standardWriter.WriteAttributeString('key', $standardSource[0])
        $standardWriter.WriteAttributeString('value', $standardSource[1])
        $standardWriter.WriteEndElement()
    }
    $standardWriter.WriteEndElement()
    $standardWriter.WriteEndElement()
}
finally { $standardWriter.Dispose() }
Push-Location $standardRepository
try {
    foreach ($standardProject in @('pki-module', 'etee-crypto', 'library-core', 'services')) {
        & $DotNetPath pack "$standardProject/$standardProject.csproj" -c Release -p:TargetFrameworks=netstandard2.0 -p:GeneratePackageOnBuild=false -p:SignAssembly=false "-p:Version=$standardVersion" "-p:PackageVersion=$standardVersion" --output $standardFeed --source https://api.nuget.org/v3/index.json
        if ($LASTEXITCODE -ne 0) { throw "Packing $standardProject failed." }
    }
    & $DotNetPath restore compatibility-tests/compatibility-tests.csproj -p:TargetFrameworks=net8.0 -p:UseStandardPackages=true "-p:StandardLibraryVersion=$standardVersion" --configfile $standardConfig
    if ($LASTEXITCODE -ne 0) { throw 'Package-consumer restore failed.' }
    & $DotNetPath test compatibility-tests/compatibility-tests.csproj -f net8.0 -p:TargetFrameworks=net8.0 -p:UseStandardPackages=true "-p:StandardLibraryVersion=$standardVersion" --no-restore --results-directory $standardResults --logger 'trx;LogFileName=package-consumer.trx' --logger 'console;verbosity=minimal'
    if ($LASTEXITCODE -ne 0) { throw '.NET Standard package-consumer tests failed.' }
}
finally { Pop-Location }
