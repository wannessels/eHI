# Supported targets and continuous integration

The PKI, core, crypto and services libraries build for **net462, netstandard2.0, net6.0 and net8.0**. This restores the previous Framework/Standard/.NET 6 targets while retaining the optimized .NET 8 implementation. The test projects additionally target **net472 and net481** to exercise consumers built for those Framework versions.

Restoring these targets does not undo every public API change from the native migration. In particular, the new revocation evidence types and required async interface members remain. Review the [migration guide](native-crypto-migration.md) when updating an application.

| Target | Crypto implementation | Validation |
|---|---|---|
| .NET 8 / .NET 6 | Platform CMS/timestamp APIs and native streaming primitives, with selectable BouncyCastle message crypto | Full performance/regression suite and the existing self-contained test projects on Windows and Linux |
| .NET Framework 4.6.2 | Portable CMS/timestamp metadata backed by BouncyCastle, with the same streaming, signature, revocation and admission policy; selectable message primitives | Shared security, cache, revocation, ETK, PKCS#12 and B/T/LT/LTA tests, plus existing self-contained tests; net462/net472/net481 consumer builds on Windows |
| .NET Standard 2.0 | Portable metadata and compatibility implementations for unavailable stream/crypto APIs | Package-only consumer tests on Windows and Linux, explicitly asserting that the loaded libraries are the Standard assets |

Framework-targeted tests run on the runner's installed .NET Framework 4.x runtime, which is updated in place. Targeting net462 is not a claim that CI runs an unpatched 4.6.2 installation. Likewise, restoring .NET 6 compatibility does not extend Microsoft's support lifecycle for that runtime.

## Runtime-specific details

- Framework/Standard builds use `PortableTimestampToken` and related metadata types in `Egelke.EHealth.Client.Pki.Compatibility` where the platform does not provide RFC 3161 APIs. The timestamp extension methods expose that type on those targets; `TokenInfo.Timestamp`, `TokenInfo.HashAlgorithmId`, `GetMessageHash`, `IsMatch` and validation remain available. .NET 6/8 continue to expose the platform `Rfc3161TimestampToken`.
- BouncyCastle is a PKI dependency on Framework/Standard. It is not a PKI/core dependency on .NET 6/8. Portable timestamp verification checks the signature, ESS signing-certificate binding, timestamping purpose and certificate validity at generation time; trust and revocation use the shared verifier.
- The bounded `X509CertificateLoader` validates PKCS#12 imports on every target. On older runtimes, BouncyCastle reads aliases after that validation. Framework keys permitting encrypted export but not plaintext parameter export can be exported through password-protected PKCS#12 by the explicitly selected BouncyCastle backend; non-exportable keys still fail export.
- PSS is still the RSA signing default. A PKCS#1-only provider needs the explicit option described in [the review follow-up](performance-review-follow-up.md). Native mode can sign without private-key export. Older runtimes may retain a single ECDSA provider handle rather than clone it.
- Framework/Standard APIs lack `CustomRootTrust`. The platform builds the path using supplied anchors, and the compatibility layer accepts only a terminal certificate present in the explicit trust set. It replaces only the platform's unknown-anchor/partial-anchor statuses; signature, constraints, validity and usage errors remain failures. System trust continues to go through the platform on each call. `DisableCertificateDownloads` cannot suppress the older platform's automatic intermediate retrieval; its timeout still applies.
- The Standard core assembly uses WCF 4.10.3 because modern WCF packages do not implement that target. It supplies the missing claim value type and an internal certificate proof token used by the custom WS-Security signer. Normal NuGet selection uses runtime-specific library assets for Framework and .NET 6/8 applications; prefer those over forcing Standard assets while independently upgrading WCF.

## GitHub Actions coverage

[The workflow](../.github/workflows/test.yml) runs on pushes, pull requests and manual dispatch. It uses pinned action revisions and read-only repository permissions.

1. Build the entire solution in Debug and Release for all declared targets, and build the benchmark project. CI sets `SignAssembly=false` because the private release signing key is not in the repository. These builds are validation artifacts, not official signed releases.
2. Run every self-contained test project on Windows for net462/net472/net481/net6.0/net8.0 and on Linux for net6.0/net8.0. The portable compatibility suite shares the actual security regressions with the modern suite, including both backends and RSA-PSS/PKCS#1 profile round trips.
3. Pack only the Standard library assets at a unique local version, restore a consuming test application from that feed, and run it on Windows/Linux. An assertion verifies that runtime-specific project assets have not accidentally replaced the Standard libraries.
4. Upload TRX results even when a test fails. Integration/hardware exclusions appear as explicit skips.

The workflow does not publish packages, change repository settings, or provision credentials. It starts on GitHub after the workflow is committed and pushed.

## Run the same tests locally

Use PowerShell 7 and a .NET 8 or newer SDK. Install the .NET 6 and .NET 8 runtimes for the modern test targets. Framework tests require Windows with .NET Framework installed; reference assemblies are restored from Microsoft's reference-assembly package, so manual targeting-pack installation is unnecessary.

```powershell
./eng/test.ps1 -Framework net8.0
./eng/test.ps1 -Framework net6.0
./eng/test.ps1 -Framework net462  # Windows
./eng/test.ps1 -Framework net472  # Windows
./eng/test.ps1 -Framework net481  # Windows
./eng/test-standard.ps1
```

If a different/older `dotnet` is first on PATH, both scripts accept `-DotNetPath`, for example `-DotNetPath "$env:USERPROFILE/.dotnet/dotnet.exe"`. The Standard test uses a separate package-consumer restore configuration; run the ordinary test script without `-NoRestore` afterwards to restore all project-reference targets again.

Results are written below `artifacts/test-results`. The scripts fail if any included project fails and continue through the other test projects so their results are retained.

## Tests requiring an external environment

Some original tests depend on private eHealth P12/password/license/patient fixtures, live eHealth/OCSP/TSA endpoints, a separately running Java SOAP mock, installed fixture trust anchors, or a physical eID. They cannot run reliably on an unconfigured GitHub-hosted runner. They remain in their projects and compile for every declared test target; they are not reported as passing when skipped.

- `IntegrationFact` / `IntegrationTheory` require `EHI_RUN_INTEGRATION=1` in a prepared test environment. This includes the Java interoperability test, which also needs its matching JAR/JDK and fixtures. Some legacy fixture tests install certificate trust anchors, so use a disposable, deliberately prepared environment.
- `HardwareFact` requires `EHI_RUN_HARDWARE_TESTS=1` and an attached eID/operator. Public CI never sets it.
- Existing unconditional skips for unfinished tests remain unchanged.

Only enable these flags after supplying the required test credentials and services. Do not put private fixtures into the repository, fork-PR jobs, or publicly uploaded logs. The default CI runs generated/local and committed-public-fixture tests, including revocation through loopback responders, without production credentials or root-store installation.

For the installation mechanism and runner prerequisites, see Microsoft's [dotnet-install reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script) and GitHub's [Windows runner inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md).
