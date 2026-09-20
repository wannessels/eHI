using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Xunit;

public class NativeRsaPssTests
{
    private static byte[] Content(CmsSignedData cms)
    { using var output = new MemoryStream(); cms.SignedContent.Write(output); return output.ToArray(); }
    internal static byte[] BouncySign(byte[] bytes, RSA key, byte[] id)
    {
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", DotNetUtilities.GetRsaKeyPair(key).Private), id));
        return generator.Generate(new CmsProcessableByteArray(bytes), true).GetEncoded();
    }
    internal static byte[] BouncySeal(byte[] bytes, RSA sender, byte[] senderId, SecretKey recipient, byte[] kek)
    {
        var inner = BouncySign(bytes, sender, senderId);
        var generator = new CmsEnvelopedDataGenerator();
        generator.AddKekRecipient("AES", new KeyParameter(kek), recipient.Id);
        var encrypted = generator.Generate(new CmsProcessableByteArray(inner), "2.16.840.1.101.3.4.1.2").GetEncoded();
        return BouncySign(encrypted, sender, senderId);
    }
    internal static byte[] BouncyUnseal(byte[] bytes, RSA sender, byte[] kek)
    {
        var outer = new CmsSignedData(bytes);
        Assert.True(outer.GetSignerInfos().GetSigners().Single().Verify(DotNetUtilities.GetRsaPublicKey(sender)));
        var encrypted = Content(outer);
        var envelope = new CmsEnvelopedData(encrypted);
        var recipient = envelope.GetRecipientInfos().GetRecipients().First();
        var inner = new CmsSignedData(recipient.GetContent(new KeyParameter(kek)));
        Assert.True(inner.GetSignerInfos().GetSigners().Single().Verify(DotNetUtilities.GetRsaPublicKey(sender)));
        return Content(inner);
    }
    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public async Task NativeAndBouncyCastleCmsInteroperateInBothDirections(int bits)
    {
        using var rsa = RSA.Create(bits); var sender = new WebKey(rsa);
        byte[] kek = RandomNumberGenerator.GetBytes(16), data = RandomNumberGenerator.GetBytes(32000);
        var recipient = new SecretKey(new byte[] { 1, 2, 3 }, kek);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
        try
        {
            using (var input = new MemoryStream(data))
            using (var sealedData = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>()))
            using (var copy = new MemoryStream())
            { sealedData.CopyTo(copy); Assert.Equal(data, BouncyUnseal(copy.ToArray(), rsa, kek)); }
            using var legacy = new MemoryStream(BouncySeal(data, rsa, sender.Id, recipient, kek));
            var result = await receiver.UnsealAsync(legacy, sender, recipient);
            using (result.UnsealedData)
            using (var clear = new MemoryStream())
            { result.UnsealedData.CopyTo(clear); Assert.Equal(data, clear.ToArray()); Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus); }
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
    [Fact]
    public async Task RsaWebKeyRecipientRoundTrips()
    {
        using var senderKey = RSA.Create(2048); using var recipientKey = RSA.Create(2048);
        var sender = new WebKey(senderKey); var recipient = new WebKey(recipientKey);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), recipient);
        try
        {
            using var input = new MemoryStream(new byte[32768]); using var sealedData = await sealer.SealAsync(input, recipient);
            var result = await receiver.UnsealAsync(sealedData, sender); using (result.UnsealedData) Assert.Equal(input.Length, result.UnsealedData.Length);
            Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
}
