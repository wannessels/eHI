using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services.Mda;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

[Collection("Revocation")]
public class NativeEnvelopeTests
{
    [Fact]
    public void ProductionAssembliesHaveNoBouncyCastleReferences()
    {
        foreach (var assembly in new[] { typeof(EHealthP12).Assembly, typeof(EncryptionToken).Assembly, typeof(EhBinding).Assembly, typeof(MdaClient).Assembly })
            Assert.DoesNotContain(assembly.GetReferencedAssemblies(), reference => reference.Name.Contains("BouncyCastle", StringComparison.OrdinalIgnoreCase));
    }
    [Theory]
    [InlineData(16)] [InlineData(24)] [InlineData(32)]
    public async Task AllAesKeyWrapSizesInteroperate(int length)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        byte[] kek = RandomNumberGenerator.GetBytes(length), payload = RandomNumberGenerator.GetBytes(1024);
        var recipient = new SecretKey(new byte[] { 9 }, kek);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
        try
        {
            using var input = new MemoryStream(payload); using var output = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>()); using var copy = new MemoryStream();
            output.CopyTo(copy); Assert.Equal(payload, NativeRsaPssTests.BouncyUnseal(copy.ToArray(), rsa, kek));
            using var legacy = new MemoryStream(NativeRsaPssTests.BouncySeal(payload, rsa, sender.Id, recipient, kek));
            var result = await receiver.UnsealAsync(legacy, sender, recipient); using(result.UnsealedData) Assert.Equal(payload.Length, result.UnsealedData.Length);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
    [Fact]
    public async Task CertificateRecipientInteroperatesAndWrongExplicitKekDoesNotFallBack()
    {
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Root", BigInteger.One, rootKey, null, null);
        var receiverPair = PkiFixture.NewKey(); var receiverCertificate = PkiFixture.MakeCert("CN=Recipient", BigInteger.Two, receiverPair, root, rootKey, keyUsage: 48);
        using var rootCert = new X509Certificate2(root.GetEncoded()); using var publicCert = new X509Certificate2(receiverCertificate.GetEncoded());
        using var receiverKey = RSA.Create(); receiverKey.ImportParameters(DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)receiverPair.Private));
        using var cert = publicCert.CopyWithPrivateKey(receiverKey);
        using var senderKey = RSA.Create(2048); var sender = new WebKey(senderKey);
        var previous = X509CertificateHelper.CustomTrustStore; X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null, new X509Certificate2Collection(cert), new X509Certificate2Collection(rootCert), Array.Empty<WebKey>());
        try
        {
            var data = RandomNumberGenerator.GetBytes(1234);
            using var input = new MemoryStream(data); using var output = await sealer.SealAsync(input, publicCert); using var copy = new MemoryStream(); output.CopyTo(copy);
            var outer = new CmsSignedData(copy.ToArray()); using var encrypted = new MemoryStream(); outer.SignedContent.Write(encrypted);
            var envelope = new CmsEnvelopedData(encrypted.ToArray());
            var legacyInner = new CmsSignedData(envelope.GetRecipientInfos().GetRecipients().Single().GetContent(receiverPair.Private));
            Assert.True(legacyInner.GetSignerInfos().GetSigners().Single().Verify(DotNetUtilities.GetRsaPublicKey(senderKey)));
            using var nativeInput = new MemoryStream(copy.ToArray()); var result = await receiver.UnsealAsync(nativeInput, sender);
            using(result.UnsealedData) using(var clear = new MemoryStream()) { result.UnsealedData.CopyTo(clear); Assert.Equal(data, clear.ToArray()); }
            Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            using var wrongInput = new MemoryStream(copy.ToArray());
            await Assert.ThrowsAsync<InvalidMessageException>(() => receiver.UnsealAsync(wrongInput, sender, new SecretKey(new byte[] { 77 }, new byte[16])));
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); X509CertificateHelper.CustomTrustStore = previous; }
    }
    [Fact]
    public async Task ModifiedSignatureIsNotAcceptedAndTrailingDataIsRejected()
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa); var secret = new SecretKey(new byte[] { 1 }, RandomNumberGenerator.GetBytes(16));
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
        try
        {
            using var input = new MemoryStream(new byte[1024]); using var output = await sealer.SealAsync(input, secret, Array.Empty<EncryptionToken>()); using var copy = new MemoryStream(); output.CopyTo(copy);
            byte[] original = copy.ToArray(), corrupt = (byte[])original.Clone(); corrupt[corrupt.Length - 1] ^= 1;
            using var badInput = new MemoryStream(corrupt); var result = await receiver.UnsealAsync(badInput, sender, secret);
            using(result.UnsealedData) Assert.Equal(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            using var trailing = new MemoryStream(original.Concat(new byte[] { 0 }).ToArray());
            await Assert.ThrowsAsync<InvalidMessageException>(() => receiver.UnsealAsync(trailing, sender, secret));
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
}
