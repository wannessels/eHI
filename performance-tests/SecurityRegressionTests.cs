using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Store;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Xunit;
using TrustStatus = Egelke.EHealth.Etee.Crypto.Status.TrustStatus;
using BCert = Org.BouncyCastle.X509.X509Certificate;
using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using CmsTime = Org.BouncyCastle.Asn1.Cms.Time;

[Collection("Revocation")]
public class SecurityRegressionTests
{
    private static X509Certificate2 WithKey(BCert cert, AsymmetricCipherKeyPair pair)
    {
#if LEGACY_RUNTIME
        return PkiFixture.WithKey(cert, pair);
#else
        using var rsa = RSA.Create();
        rsa.ImportParameters(DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)pair.Private));
        using var publicCert = new X509Certificate2(cert.GetEncoded());
        return publicCert.CopyWithPrivateKey(rsa);
#endif
    }

    private static byte[] Sign(byte[] content, RSA key, byte[] id, DateTime date)
    {
        var attributes = new AttributeTable(new Dictionary<DerObjectIdentifier, object>
        { [CmsAttributes.SigningTime] = new CmsAttribute(CmsAttributes.SigningTime, new DerSet(new CmsTime(date))) });
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder()
            .WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(attributes))
            .Build(new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", DotNetUtilities.GetRsaKeyPair(key).Private), id));
        return generator.Generate(new CmsProcessableByteArray(content), true).GetEncoded();
    }

    private static byte[] Content(CmsSignedData signed)
    {
        using var content = new MemoryStream(); signed.SignedContent.Write(content); return content.ToArray();
    }

    [Theory]
    [InlineData(true, false, false)] [InlineData(false, false, false)]
    [InlineData(true, true, false)] [InlineData(false, true, false)]
    [InlineData(true, false, true)] [InlineData(false, false, true)]
    [InlineData(true, true, true)] [InlineData(false, true, true)]
    public async Task SelectsRecipientAcrossEntriesAtSigningTime(bool native, bool reverseOrder, bool historical)
    {
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Rotation Root", BigInteger.One, rootKey, null, null);
        var oldKey = PkiFixture.NewKey(); var newKey = PkiFixture.NewKey();
        var old = PkiFixture.MakeCert("CN=Old", reverseOrder ? BigInteger.Three : BigInteger.Two, oldKey, root, rootKey,
            keyUsage: 48, notBefore: DateTime.UtcNow.AddHours(-20), notAfter: DateTime.UtcNow.AddHours(-1));
        var current = PkiFixture.MakeCert("CN=Current", reverseOrder ? BigInteger.Two : BigInteger.Three, newKey, root, rootKey,
            keyUsage: 48, notBefore: DateTime.UtcNow.AddMinutes(-30));
        using var rootCert = new X509Certificate2(root.GetEncoded());
        using var oldCert = WithKey(old, oldKey); using var newCert = WithKey(current, newKey);
        using var senderRsa = RuntimeCompat.CreateRsa(2048); var sender = new WebKey(senderRsa);
        var previous = X509CertificateHelper.CustomTrustStore;
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null,
            new X509Certificate2Collection(new[] { oldCert, newCert }), new X509Certificate2Collection(rootCert));
        try
        {
            byte[] payload = { 1, 2, 3 };
            using var input = new MemoryStream(payload); using var sealedData = await sealer.SealAsync(input, oldCert, newCert);
            using var copy = new MemoryStream(); sealedData.CopyTo(copy);
            var outer = new CmsSignedData(copy.ToArray());
            using var dated = new MemoryStream(Sign(Content(outer), senderRsa, sender.Id,
                historical ? DateTime.UtcNow.AddHours(-2) : DateTime.UtcNow));
            var result = await receiver.UnsealAsync(dated, sender);
            using (result.UnsealedData)
            {
                Assert.Equal((historical ? oldCert : newCert).Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
                Assert.Equal(CryptoEncoding.SubjectKeyIdentifier(historical ? oldCert : newCert), result.SecurityInformation.Encryption.SubjectId);
                Assert.True(result.SecurityInformation.TrustStatus == TrustStatus.Full, result.SecurityInformation.ToString());
                using var clear = new MemoryStream(); result.UnsealedData.CopyTo(clear); Assert.Equal(payload, clear.ToArray());
            }
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); X509CertificateHelper.CustomTrustStore = previous; }
    }

    [Fact]
    public async Task NativeRecipientIdentityMustUnwrapTheActualContentKey()
    {
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Binding Root", BigInteger.One, rootKey, null, null);
        var oldKey = PkiFixture.NewKey(); var newKey = PkiFixture.NewKey();
        using var old = WithKey(PkiFixture.MakeCert("CN=Old", BigInteger.Two, oldKey, root, rootKey, keyUsage: 48, notAfter: DateTime.UtcNow.AddHours(-1)), oldKey);
        using var current = WithKey(PkiFixture.MakeCert("CN=Current", BigInteger.Three, newKey, root, rootKey, keyUsage: 48), newKey);
        using var rootCert = new X509Certificate2(root.GetEncoded());
        using var senderRsa = RuntimeCompat.CreateRsa(2048); var sender = new WebKey(senderRsa);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null,
            new X509Certificate2Collection(new[] { old, current }), new X509Certificate2Collection(rootCert));
        try
        {
            using var input = new MemoryStream(new byte[] { 1, 2, 3 });
            using var sealedData = await sealer.SealAsync(input, old, current);
            using var copy = new MemoryStream(); sealedData.CopyTo(copy);
            var outer = new CmsSignedData(copy.ToArray());
            var content = ContentInfo.GetInstance(Content(outer));
            var envelope = EnvelopedData.GetInstance(content.Content);
            using var currentRsa = current.GetRSAPublicKey();
            var changed = envelope.RecipientInfos.Cast<Asn1Encodable>().Select(value =>
            {
                var recipient = KeyTransRecipientInfo.GetInstance(RecipientInfo.GetInstance(value).Info);
                if (!IssuerAndSerialNumber.GetInstance(recipient.RecipientIdentifier.ID).SerialNumber.Value.Equals(BigInteger.Three)) return value;
                return new RecipientInfo(new KeyTransRecipientInfo(recipient.RecipientIdentifier, recipient.KeyEncryptionAlgorithm,
                    new DerOctetString(currentRsa.Encrypt(RuntimeCompat.RandomBytes(16), RSAEncryptionPadding.Pkcs1))));
            }).ToArray();
            var altered = new ContentInfo(content.ContentType, new EnvelopedData(envelope.OriginatorInfo, new DerSet(changed), envelope.EncryptedContentInfo, envelope.UnprotectedAttrs));
            using var message = new MemoryStream(Sign(altered.GetEncoded(), senderRsa, sender.Id, DateTime.UtcNow));
            var error = await Assert.ThrowsAsync<InvalidMessageException>(() => receiver.UnsealAsync(message, sender));
            Assert.Contains("different content encryption keys", error.Message);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    public async Task NullLevelChecksDownloadedAndEmbeddedRevocation(bool native, bool embedded)
    {
        using var server = new PkiFixture.FixtureServer();
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Revocation Root", BigInteger.One, rootKey, null, null);
        var signerKey = PkiFixture.NewKey();
        var signer = PkiFixture.MakeCert("CN=Revoked", BigInteger.Two, signerKey, root, rootKey, crl: embedded ? null : server.Url + "crl");
        byte[] crl = PkiFixture.MakeCrl(root, rootKey, revoked: BigInteger.Two).GetEncoded(); server.Crl = crl;
        using var rootCert = new X509Certificate2(root.GetEncoded());
        var previous = X509CertificateHelper.CustomTrustStore;
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert); RevocationCache.Clear();
        var generator = new CmsSignedDataGenerator(); var builder = new SignerInfoGeneratorBuilder();
        if (embedded)
        {
            var oid = new DerObjectIdentifier(CryptoEncoding.RevocationAttribute);
            var values = new DerSequence(new DerTaggedObject(true, 0, new DerSequence(Asn1Object.FromByteArray(crl))));
            builder.WithUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(new Dictionary<DerObjectIdentifier, object>
            { [oid] = new CmsAttribute(oid, new DerSet((Asn1Encodable)values)) })));
        }
        generator.AddSignerInfoGenerator(builder.Build(new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", signerKey.Private), signer));
        generator.AddCertificates(CollectionUtilities.CreateStore(new[] { signer, root }));
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, native).Create(null);
        try
        {
            using var data = new MemoryStream(generator.Generate(new CmsProcessableByteArray(new byte[] { 42 }), true).GetEncoded());
            var result = await verifier.VerifyAsync(data);
            Assert.Equal(TrustStatus.None, result.TrustStatus);
            Assert.Contains(CertSecurityViolation.Revoked, result.Subject.SecurityViolations);
            Assert.Equal(embedded ? 0 : 1, server.CrlRequests);
        }
        finally { (verifier as IDisposable)?.Dispose(); X509CertificateHelper.CustomTrustStore = previous; RevocationCache.Clear(); }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task NullLevelUnsealDoesNotTrustARevokedSigner(bool native)
    {
        using var server = new PkiFixture.FixtureServer();
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Unseal Revocation Root", BigInteger.One, rootKey, null, null);
        var signerKey = PkiFixture.NewKey();
        using var signer = WithKey(PkiFixture.MakeCert("CN=Revoked", BigInteger.Two, signerKey, root, rootKey, crl: server.Url + "crl"), signerKey);
        server.Crl = PkiFixture.MakeCrl(root, rootKey, revoked: BigInteger.Two).GetEncoded();
        using var rootCert = new X509Certificate2(root.GetEncoded());
        var previous = X509CertificateHelper.CustomTrustStore;
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert); RevocationCache.Clear();
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, native, RSASignaturePadding.Pkcs1).Create(Level.B_Level, signer);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        var secret = new SecretKey(new byte[] { 1 }, new byte[16]);
        try
        {
            using var input = new MemoryStream(new byte[] { 42 }); using var message = await sealer.SealAsync(input, secret, Array.Empty<EncryptionToken>());
            var result = await receiver.UnsealAsync(message, secret);
            using (result.UnsealedData) Assert.Equal(TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.Equal(1, server.CrlRequests);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); X509CertificateHelper.CustomTrustStore = previous; RevocationCache.Clear(); }
    }
}
