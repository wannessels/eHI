using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using TrustStatus = Egelke.EHealth.Etee.Crypto.Status.TrustStatus;

[Collection("Revocation")]
public class RsaPaddingTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ExplicitPkcs1SignsWithoutExportAndInteroperates(bool nativeReceiver)
    {
        using var provider = new Pkcs1OnlyRsa(); var sender = new WebKey(new byte[] { 1, 2 }, provider);
        var secret = new SecretKey(new byte[] { 3 }, new byte[16]);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true, RSASignaturePadding.Pkcs1).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, nativeReceiver).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        try
        {
            byte[] payload = { 1, 2, 3 };
            using var input = new MemoryStream(payload); using var message = await sealer.SealAsync(input, secret, Array.Empty<EncryptionToken>());
            using var copy = new MemoryStream(); message.CopyTo(copy);
            var cms = new SignedCms(); cms.Decode(copy.ToArray());
            Assert.Equal(CryptoEncoding.Rsa, cms.SignerInfos[0].SignatureAlgorithm.Value);
            message.Position = 0;
            var result = await receiver.UnsealAsync(message, sender, secret);
            using (result.UnsealedData)
            {
                Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                Assert.Equal(TrustStatus.Full, result.SecurityInformation.TrustStatus);
                using var clear = new MemoryStream(); result.UnsealedData.CopyTo(clear); Assert.Equal(payload, clear.ToArray());
            }
            Assert.Equal(2, provider.Pkcs1Signatures); Assert.Equal(0, provider.PrivateExports);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }

    [Fact]
    public async Task SealerCapturesPaddingAndPssFailureNeverFallsBack()
    {
        var previous = Settings.Default.RsaSignaturePadding;
        using var provider = new Pkcs1OnlyRsa(); var sender = new WebKey(new byte[] { 1 }, provider);
        var secret = new SecretKey(new byte[] { 2 }, new byte[16]);
        IDataSealer pkcs1 = null, pss = null;
        try
        {
            Settings.Default.RsaSignaturePadding = RSASignaturePadding.Pkcs1;
            var factory = new DataSealerFactory(NullLoggerFactory.Instance, true);
            pkcs1 = factory.Create(Level.B_Level, sender);
            Settings.Default.RsaSignaturePadding = RSASignaturePadding.Pss;
            pss = factory.Create(Level.B_Level, sender);
            using var input = new MemoryStream(new byte[] { 42 });
            using var output = await pkcs1.SealAsync(input, secret, Array.Empty<EncryptionToken>());
            Assert.Equal(2, provider.Pkcs1Signatures);
            input.Position = 0;
            await Assert.ThrowsAsync<CryptographicException>(() => pss.SealAsync(input, secret, Array.Empty<EncryptionToken>()));
            Assert.Equal(2, provider.Pkcs1Signatures); Assert.Equal(1, provider.PssAttempts); Assert.Equal(0, provider.PrivateExports);
        }
        finally { (pkcs1 as IDisposable)?.Dispose(); (pss as IDisposable)?.Dispose(); Settings.Default.RsaSignaturePadding = previous; }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task BothBackendsEmitTheExplicitPadding(bool native)
    {
        using var rsa = RuntimeCompat.CreateRsa(2048); var sender = new WebKey(rsa);
        foreach (var padding in new[] { RSASignaturePadding.Pss, RSASignaturePadding.Pkcs1 })
        {
            var sealer = new DataSealerFactory(NullLoggerFactory.Instance, native, padding).Create(Level.B_Level, sender);
            try
            {
                using var input = new MemoryStream(new byte[] { 42 });
                using var message = await sealer.SealAsync(input, new SecretKey(new byte[] { 2 }, new byte[16]), Array.Empty<EncryptionToken>());
                using var copy = new MemoryStream(); message.CopyTo(copy);
                var cms = new SignedCms(); cms.Decode(copy.ToArray());
                if (padding == RSASignaturePadding.Pss) Assert.Equal(CryptoEncoding.RsaPss, cms.SignerInfos[0].SignatureAlgorithm.Value);
                else Assert.Contains(cms.SignerInfos[0].SignatureAlgorithm.Value, new[] { CryptoEncoding.Rsa, "1.2.840.113549.1.1.11" });
                // Independent CMS verifier, including BouncyCastle algorithm-protection attributes.
                var legacy = new Org.BouncyCastle.Cms.CmsSignedData(copy.ToArray());
                foreach (var signer in legacy.GetSignerInfos().GetSigners()) Assert.True(signer.Verify(Org.BouncyCastle.Security.DotNetUtilities.GetRsaPublicKey(rsa)));
            }
            finally { (sealer as IDisposable)?.Dispose(); }
        }
    }

    [ServiceContract]
    public interface ITestPort { [OperationContract] void Unused(); }
    private sealed class TestClient : ServiceClient<ITestPort>
    {
        internal TestClient(X509Certificate2 certificate) : base(new BasicHttpBinding(), new EndpointAddress("http://localhost/unused"))
        { ClientCredentials.ClientCertificate.Certificate = certificate; }
        internal Task<byte[]> Encrypt(EncryptionToken token) => EncryptAsync(new byte[] { 42 }, Level.B_Level, token);
    }

#if NET6_0_OR_GREATER
    [Fact]
    public async Task ExistingServiceClientReplacesContextWhenPaddingChanges()
    {
        using var rsa = RuntimeCompat.CreateRsa(2048);
        var request = new CertificateRequest("CN=Padding Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var previousTrust = X509CertificateHelper.CustomTrustStore; var previousPadding = Settings.Default.RsaSignaturePadding;
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(certificate);
        var client = new TestClient(certificate);
        var token = new EncryptionToken(new Org.BouncyCastle.Cms.CmsSignedDataGenerator()
            .Generate(new Org.BouncyCastle.Cms.CmsProcessableByteArray(certificate.RawData), true).GetEncoded());
        try
        {
            foreach (var padding in new[] { RSASignaturePadding.Pss, RSASignaturePadding.Pkcs1 })
            {
                Settings.Default.RsaSignaturePadding = padding;
                var cms = new SignedCms(); cms.Decode(await client.Encrypt(token)); cms.CheckSignature(true);
                Assert.Equal(padding == RSASignaturePadding.Pss ? CryptoEncoding.RsaPss : CryptoEncoding.Rsa, cms.SignerInfos[0].SignatureAlgorithm.Value);
            }
        }
        finally { client.Abort(); token.ToCertificate().Dispose(); Settings.Default.RsaSignaturePadding = previousPadding; X509CertificateHelper.CustomTrustStore = previousTrust; }
    }
#endif

    private sealed class Pkcs1OnlyRsa : RSA
    {
        private readonly RSA inner = RuntimeCompat.CreateRsa(2048);
        internal int Pkcs1Signatures, PssAttempts, PrivateExports;
        public override int KeySize { get => inner.KeySize; set => inner.KeySize = value; }
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters) { PrivateExports++; throw new CryptographicException("Private key is non-exportable"); }
            return inner.ExportParameters(false);
        }
        public override void ImportParameters(RSAParameters parameters) => throw new NotSupportedException();
        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => inner.Encrypt(data, padding);
        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) => inner.Decrypt(data, padding);
        public override byte[] SignHash(byte[] hash, HashAlgorithmName algorithm, RSASignaturePadding padding)
        {
            if (padding != RSASignaturePadding.Pkcs1) { PssAttempts++; throw new CryptographicException("Provider supports PKCS#1 signing only"); }
            Pkcs1Signatures++; return inner.SignHash(hash, algorithm, padding);
        }
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName algorithm, RSASignaturePadding padding) => inner.VerifyHash(hash, signature, algorithm, padding);
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
