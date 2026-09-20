using System.Diagnostics;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

// A pharmacy retrieving one prescription: seal the request to Recip-e, unseal the sealed response,
// then unseal the prescriber's time-marked prescription with its KGSS key. The certificate hierarchies
// follow the Belgian ones (root > government > eHealth-platform CA; root > Citizen CA) and the Citizen CA
// CRL defaults to the live eID list's 350k entries (12 MiB). No live eHealth endpoint is contacted.
internal static class PharmacyProfiles
{
    private const int RequestBytes = 1024, PrescriptionBytes = 4096;

    internal static async Task<object> RunAsync(int concurrency, int requests, int prescribers, int citizenCrlEntries, int ehealthCrlEntries)
    {
        if (prescribers < 1) throw new ArgumentOutOfRangeException(nameof(prescribers));
        await using var pki = await EHealthPki.StartAsync(prescribers, citizenCrlEntries, ehealthCrlEntries);
        X509CertificateHelper.CustomTrustStore = pki.Authorities;
        X509CertificateHelper.DisableCertificateDownloads = true;
        RevocationCache.Clear(); ChainCache.Clear();
        var sealers = new DataSealerFactory(NullLoggerFactory.Instance, true);
        var unsealers = new DataUnsealerFactory(NullLoggerFactory.Instance, true);
        var pharmacySealer = sealers.Create(Level.B_Level, pki.Pharmacy);
        var pharmacyUnsealer = unsealers.Create(Level.B_Level, new X509Certificate2Collection(pki.PharmacyEncryption), new X509Certificate2Collection());
        var prescriptionUnsealer = unsealers.CreateFromTimemarkAuthority(Level.LT_Level, new RecipeTimemark(), new X509Certificate2Collection(), new X509Certificate2Collection());
        var recipeSealer = sealers.Create(Level.B_Level, pki.Recipe);
        try
        {
            byte[] request = RandomNumberGenerator.GetBytes(RequestBytes), prescription = RandomNumberGenerator.GetBytes(PrescriptionBytes);
            var responses = new (byte[] Sealed, SecretKey Key)[prescribers];
            for (int i = 0; i < prescribers; i++)
            {
                var key = new SecretKey(BitConverter.GetBytes(i), RandomNumberGenerator.GetBytes(32));
                var prescriber = sealers.CreateForTimemarkAuthority(Level.T_Level, pki.Prescribers[i]);
                try
                {
                    using var content = new MemoryStream(prescription, false);
                    using var sealedPrescription = await prescriber.SealAsync(content, key, Array.Empty<EncryptionToken>());
                    using var sealedResponse = await recipeSealer.SealAsync(sealedPrescription, pki.PharmacyEncryption);
                    responses[i] = (ToArray(sealedResponse), key);
                }
                finally { (prescriber as IDisposable)?.Dispose(); }
            }
            var policy = new OperationPolicy(concurrency, TimeSpan.FromMinutes(2));
            int next = -1;
            async Task Request() => await policy.RunAsync(async _ =>
            {
                var response = responses[Interlocked.Increment(ref next) % prescribers];
                using var input = new MemoryStream(request, false);
                using var sealedRequest = await pharmacySealer.SealAsync(input, pki.RecipeEncryption);
                using var sealedResponse = new MemoryStream(response.Sealed, false);
                var envelope = await pharmacyUnsealer.UnsealAsync(sealedResponse);
                using (envelope.UnsealedData)
                {
                    Check(envelope.SecurityInformation);
                    var result = await prescriptionUnsealer.UnsealAsync(envelope.UnsealedData, response.Key);
                    using (result.UnsealedData)
                    {
                        Check(result.SecurityInformation);
                        if (result.UnsealedData.Length != PrescriptionBytes) throw new Exception("Prescription length mismatch");
                    }
                }
                return 0;
            });
            long cold = Stopwatch.GetTimestamp(); await Request(); double coldMs = Stopwatch.GetElapsedTime(cold).TotalMilliseconds;
            var rounds = await ClosedLoop.RunAsync(concurrency, requests, Request,
                () => new { CrlDownloads = Volatile.Read(ref pki.CrlDownloads), RevocationCacheEntries = RevocationCache.Count, RevocationCacheEstimatedBytes = RevocationCache.EstimatedSizeBytes, ChainCacheEntries = ChainCache.Count, ChainCacheHits = ChainCache.Hits, ChainCacheMisses = ChainCache.Misses });
            return new
            {
                Method = "Closed-loop pharmacy workers: seal a request to Recip-e, unseal the Recip-e response, unseal the time-marked prescription with its KGSS key at LT level. Chains: root > government > eHealth-platform CA (pharmacy, Recip-e), root > Citizen CA (prescribers). CRLs from an in-process HTTP server, no OCSP responder, no live eHealth endpoints.",
                Prescribers = prescribers, RequestBytes, PrescriptionBytes,
                CitizenCrlEntries = citizenCrlEntries, CitizenCrlBytes = pki.CitizenCrl.LongLength, CitizenCrlParseMs = ParseMs(pki.CitizenCrl),
                EHealthCrlEntries = ehealthCrlEntries, EHealthCrlBytes = pki.EHealthCrl.LongLength,
                CommittedCitizenCrl = CommittedCitizenCrl(), ColdFirstRequestMs = coldMs, Rounds = rounds
            };
        }
        finally
        {
            foreach (var context in new object[] { pharmacySealer, pharmacyUnsealer, prescriptionUnsealer, recipeSealer }) (context as IDisposable)?.Dispose();
            X509CertificateHelper.CustomTrustStore = null;
        }
    }

    private static void Check(UnsealSecurityInformation information)
    {
        if (information.ValidationStatus != ValidationStatus.Valid || information.TrustStatus != TrustStatus.Full)
            throw new Exception($"Unseal validation {information.ValidationStatus}, trust {information.TrustStatus}");
    }
    private static byte[] ToArray(Stream stream) { using var buffer = new MemoryStream(); stream.CopyTo(buffer); return buffer.ToArray(); }
    private static double ParseMs(byte[] crl)
    {
        long started = Stopwatch.GetTimestamp(); CertificateRevocationList.Parse(crl); return Stopwatch.GetElapsedTime(started).TotalMilliseconds;
    }
    // The committed fixture is the live eID Citizen CA 201204 list, byte-identical when checked.
    private static object? CommittedCitizenCrl()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
        {
            string path = Path.Combine(directory.FullName, "pki-test", "files", "eid79021802145.crl");
            if (!File.Exists(path)) continue;
            byte[] crl = File.ReadAllBytes(path);
            return new { Path = Path.GetRelativePath(directory.FullName, path), Bytes = crl.LongLength, ParseMs = ParseMs(crl) };
        }
        return null;
    }

    // Recip-e records when it received each prescription; this stand-in returns the signing time.
    private sealed class RecipeTimemark : ITimemarkProvider
    {
        public DateTime GetTimemark(X509Certificate2 sender, DateTime signingTime, byte[] signatureValue) => signingTime;
    }

    private sealed class EHealthPki : IAsyncDisposable
    {
        private readonly WebApplication server;
        private readonly Dictionary<string, byte[]> crls = new();
        private static readonly DateTimeOffset Issued = DateTimeOffset.UtcNow;
        internal int CrlDownloads;
        internal X509Certificate2Collection Authorities { get; } = new();
        internal X509Certificate2 Pharmacy = null!, PharmacyEncryption = null!, Recipe = null!, RecipeEncryption = null!;
        internal X509Certificate2[] Prescribers = Array.Empty<X509Certificate2>();
        internal byte[] CitizenCrl => crls["citizen"];
        internal byte[] EHealthCrl => crls["ehealth"];
        private EHealthPki(WebApplication server) { this.server = server; }

        internal static async Task<EHealthPki> StartAsync(int prescribers, int citizenCrlEntries, int ehealthCrlEntries)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
            var pki = new EHealthPki(builder.Build());
            pki.server.MapGet("/{name}.crl", (string name) => { Interlocked.Increment(ref pki.CrlDownloads); return Results.Bytes(pki.crls[name], "application/pkix-crl"); });
            await pki.server.StartAsync();
            string url = pki.server.Urls.Single() + "/";
            const X509KeyUsageFlags authority = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;
            const X509KeyUsageFlags signer = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;
            const X509KeyUsageFlags encryption = X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment;
            var root = Issue("CN=Belgium Root CA (benchmark), C=BE", null, authority, null);
            var government = Issue("CN=Government CA (benchmark), C=BE", root, authority, url + "root.crl");
            var ehealth = Issue("CN=eHealth-platform Belgium CA (benchmark), O=Federal Government, C=BE", government, authority, url + "government.crl");
            var citizen = Issue("CN=Citizen CA (benchmark), C=BE", root, authority, url + "root.crl");
            pki.Authorities.AddRange(new[] { root, government, ehealth, citizen });
            pki.Pharmacy = Issue("SERIALNUMBER=12345678, CN=\"NIHII-PHARMACY=12345678\", OU=eHealth-platform Belgium, O=Federal Government, C=BE", ehealth, signer, url + "ehealth.crl");
            pki.PharmacyEncryption = Issue("SERIALNUMBER=12345678, CN=\"NIHII-PHARMACY=12345678\", OU=ETK, O=Federal Government, C=BE", ehealth, encryption, url + "ehealth.crl");
            pki.Recipe = Issue("SERIALNUMBER=0839485926, CN=\"CBE=0839485926, RECIPE\", OU=eHealth-platform Belgium, O=Federal Government, C=BE", ehealth, signer, url + "ehealth.crl");
            pki.RecipeEncryption = Issue("SERIALNUMBER=0839485926, CN=\"CBE=0839485926, RECIPE\", OU=ETK, O=Federal Government, C=BE", ehealth, encryption, url + "ehealth.crl");
            pki.Prescribers = Enumerable.Range(0, prescribers)
                .Select(i => Issue($"SERIALNUMBER={70010100000 + i}, CN=Prescriber {i} (Signature), C=BE", citizen, signer, url + "citizen.crl")).ToArray();
            pki.crls["root"] = BuildCrl(root, 4); pki.crls["government"] = BuildCrl(government, 4);
            pki.crls["ehealth"] = BuildCrl(ehealth, ehealthCrlEntries); pki.crls["citizen"] = BuildCrl(citizen, citizenCrlEntries);
            return pki;
        }
        private static X509Certificate2 Issue(string subject, X509Certificate2? issuer, X509KeyUsageFlags usage, string? crl)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension((usage & X509KeyUsageFlags.KeyCertSign) != 0, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            if (issuer != null) request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            if (crl != null) request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(new[] { crl }));
            if (issuer == null) return request.CreateSelfSigned(Issued.AddDays(-1), Issued.AddYears(1));
            using var issued = request.Create(issuer, Issued.AddDays(-1), Issued.AddDays((usage & X509KeyUsageFlags.KeyCertSign) != 0 ? 300 : 30), Serial(RandomNumberGenerator.GetBytes(16)));
            return issued.CopyWithPrivateKey(key);
        }
        private static byte[] Serial(byte[] serial) { serial[0] = (byte)((serial[0] & 0x3F) | 0x40); return serial; }
        private static byte[] BuildCrl(X509Certificate2 issuer, int entries)
        {
            var builder = new CertificateRevocationListBuilder();
            byte[] serials = RandomNumberGenerator.GetBytes(entries * 16); var revoked = DateTimeOffset.UtcNow.AddDays(-30);
            for (int i = 0; i < entries; i++) { serials[i * 16] = (byte)((serials[i * 16] & 0x3F) | 0x40); builder.AddEntry(serials.AsSpan(i * 16, 16), revoked); }
            var now = DateTimeOffset.UtcNow;
            return builder.Build(issuer, BigInteger.One, now.AddDays(7), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, now.AddMinutes(-1));
        }
        public async ValueTask DisposeAsync()
        {
            await server.StopAsync(); await server.DisposeAsync();
            foreach (var certificate in Authorities.Cast<X509Certificate2>().Concat(new[] { Pharmacy, PharmacyEncryption, Recipe, RecipeEncryption }).Concat(Prescribers)) certificate.Dispose();
        }
    }
}
