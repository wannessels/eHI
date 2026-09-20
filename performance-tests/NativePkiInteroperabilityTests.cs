using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Store;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Xunit;
using BCert = Org.BouncyCastle.X509.X509Certificate;

[Collection("Revocation")]
public class NativePkiInteroperabilityTests
{
    [Theory]
    [InlineData("CN=Test, SERIALNUMBER=123, ST=Brussels, C=BE")]
    [InlineData("CN=\"Doe, Jane\", O=Example, C=BE")]
    public void SamlDistinguishedNamesPreserveRfc1779Formatting(string value)
    {
        var name = new X500DistinguishedName(value);
        var old = Org.BouncyCastle.Asn1.X509.X509Name.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(name.RawData));
        Assert.Equal(old.ToString(true, Org.BouncyCastle.Asn1.X509.X509Name.RFC1779Symbols), CryptoEncoding.FormatDistinguishedNameRfc1779(name));
    }
    [Fact]
    public void Pkcs12PreservesAliasesCertificatesAndPrivateKeys()
    {
        byte[] bytes = File.ReadAllBytes("fixtures/dummy.p12");
        var legacy = new Pkcs12StoreBuilder().Build(); using (var stream = new MemoryStream(bytes)) legacy.Load(stream, "test001".ToCharArray());
        using var native = new EHealthP12(bytes, "test001");
        Assert.Equal(legacy.Aliases.OrderBy(s => s), native.Keys.OrderBy(s => s));
        foreach (var alias in native.Keys)
        {
            Assert.Equal(legacy.GetCertificate(alias).Certificate.GetEncoded(), native[alias].RawData);
            Assert.Equal(legacy.IsKeyEntry(alias), native[alias].HasPrivateKey);
            Assert.Same(native[alias], native[alias]);
            if (native[alias].HasPrivateKey)
            {
                using var key = native[alias].GetRSAPrivateKey(); using var publicKey = native[alias].GetRSAPublicKey();
                byte[] signature = key.SignData(new byte[32], HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                Assert.True(publicKey.VerifyData(new byte[32], signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            }
        }
        Assert.Throws<CryptographicException>(() => new EHealthP12(bytes, "incorrect"));
    }

    [Fact]
    public void HistoricalTimestampHasEquivalentMetadataAndValidNativeSignature()
    {
        byte[] bytes = File.ReadAllBytes("fixtures/fedictTs.ts");
        var native = bytes.ToTimeStampToken();
        var legacy = new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(bytes));
        Assert.Equal(legacy.TimeStampInfo.GenTime, native.TokenInfo.Timestamp.UtcDateTime);
        Assert.Equal(legacy.TimeStampInfo.GetMessageImprintDigest(), native.TokenInfo.GetMessageHash().ToArray());
        Assert.True(native.VerifySignatureForHash(native.TokenInfo.GetMessageHash().Span, native.TokenInfo.HashAlgorithmId, out _, native.AsSignedCms().Certificates));
    }

    [Theory]
    [InlineData(Level.B_Level, true)] [InlineData(Level.B_Level, false)]
    [InlineData(Level.T_Level, true)] [InlineData(Level.T_Level, false)]
    [InlineData(Level.LT_Level, true)] [InlineData(Level.LT_Level, false)]
    [InlineData(Level.LTA_Level, true)] [InlineData(Level.LTA_Level, false)]
    public async Task CertificateAndTimestampProfilesRoundTripWithPrivateTrustAnchors(Level level, bool native)
    {
        using var server = new PkiFixture.FixtureServer();
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Test Root", BigInteger.One, rootKey, null, null);
        var authKey = PkiFixture.NewKey(); var auth = PkiFixture.MakeCert("CN=Test Signer", BigInteger.Two, authKey, root, rootKey, crl: server.Url + "crl");
        var tsaKey = PkiFixture.NewKey(); var tsa = PkiFixture.MakeCert("CN=Test TSA", BigInteger.Three, tsaKey, root, rootKey, crl: server.Url + "crl", timestamp: true);
        using var rootCert = new X509Certificate2(root.GetEncoded());
        using var signingRsa = RSA.Create(); signingRsa.ImportParameters(DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)authKey.Private));
        using var publicCert = new X509Certificate2(auth.GetEncoded()); using var signingCert = publicCert.CopyWithPrivateKey(signingRsa);
        server.Crl = PkiFixture.MakeCrl(root, rootKey).GetEncoded();
        var previous = X509CertificateHelper.CustomTrustStore;
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert);
        RevocationCache.Clear();
        var factory = new DataSealerFactory(NullLoggerFactory.Instance, native);
        var sealer = level == Level.B_Level ? factory.Create(level, signingCert) : factory.Create(level, new LocalTimestampProvider(tsa, tsaKey, root), signingCert);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(level, new X509Certificate2Collection(), new X509Certificate2Collection());
        var recipient = new SecretKey(new byte[] { 3 }, RandomNumberGenerator.GetBytes(16));
        try
        {
            byte[] data = RandomNumberGenerator.GetBytes(5000);
            using var input = new MemoryStream(data); using var output = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
            Stream completed = null;
            if (level != Level.B_Level)
            {
                using var buffer = new MemoryStream(); output.CopyTo(buffer);
                var signed = new SignedCms(); signed.Decode(buffer.ToArray());
                signed.CheckSignature(verifySignatureOnly: true); // Independent platform CMS oracle for the streamed signer.
                byte[] originalSignature = signed.SignerInfos[0].GetSignature();
                signed.RemoveCertificate(rootCert); // The completer must not duplicate the remaining signer certificate.
                using var source = new MemoryStream(signed.Encode());
                // Completion must preserve both DER (native) and BER streamed payloads,
                // including when the completing backend differs from the original sender.
                var completer = new DataCompleterFactory(NullLoggerFactory.Instance, !native).Create(level, new LocalTimestampProvider(tsa, tsaKey, root));
                try { completed = await completer.CompleteAsync(source); }
                finally { (completer as IDisposable)?.Dispose(); }
                using var copy = new MemoryStream(); completed.CopyTo(copy); completed.Position = 0;
                var after = new SignedCms(); after.Decode(copy.ToArray());
                Assert.Equal(originalSignature, after.SignerInfos[0].GetSignature());
                Assert.Equal(2, after.Certificates.Count);
                var stamp = after.SignerInfos[0].UnsignedAttributes.Cast<CryptographicAttributeObject>()
                    .Single(a => a.Oid.Value == CryptoEncoding.TimestampAttribute).Values[0].RawData.ToTimeStampToken();
                for (int iteration = 0; iteration < 2; iteration++)
                {
                    var validation = await stamp.ValidateAsync();
                    Assert.DoesNotContain(validation.TimestampStatus, status => status.Status != X509ChainStatusFlags.NoError);
                }
            }
            var result = await receiver.UnsealAsync(completed ?? output, recipient);
            completed?.Dispose();
            using (result.UnsealedData) using (var clear = new MemoryStream())
            {
                result.UnsealedData.CopyTo(clear); Assert.Equal(data, clear.ToArray());
                Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                Assert.Equal(TrustStatus.Full, result.SecurityInformation.TrustStatus);
            }
            if (level == Level.B_Level)
            {
                output.Position = 0;
                var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, native).CreateAsTimemarkAuthority(Level.T_Level);
                try
                {
                    var marked = await verifier.VerifyAsync(output, DateTime.UtcNow);
                    Assert.Equal(ValidationStatus.Valid, marked.Value.ValidationStatus);
                    Assert.Equal(marked.Value.SignatureValue, marked.TimemarkKey.SignatureValue);
                    Assert.Equal(marked.Value.SigningTime, marked.TimemarkKey.SigningTime);
                }
                finally { (verifier as IDisposable)?.Dispose(); }
            }
        }
        finally
        {
            (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose();
            X509CertificateHelper.CustomTrustStore = previous; RevocationCache.Clear();
        }
    }
    private sealed class LocalTimestampProvider : ITimestampProviderAsync
    {
        private readonly TimeStampTokenGenerator generator;
        internal LocalTimestampProvider(BCert tsa, AsymmetricCipherKeyPair key, BCert root)
        {
            generator = new TimeStampTokenGenerator(key.Private, tsa, TspAlgorithms.Sha256, "1.2.3.4.5");
            generator.SetCertificates(CollectionUtilities.CreateStore(new[] { tsa, root }));
        }
        public byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            var request = new TimeStampRequestGenerator(); request.SetCertReq(true);
            return generator.Generate(request.Generate(TspAlgorithms.Sha256, hash), BigInteger.One, DateTime.UtcNow).GetEncoded();
        }
        public Task<byte[]> GetTimestampFromDocumentHashAsync(byte[] hash, string digestMethod) => Task.FromResult(GetTimestampFromDocumentHash(hash, digestMethod));
    }
}
