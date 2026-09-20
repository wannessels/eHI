using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Store;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

// Serializes changes to global settings with the other fixture-based tests.
[Collection("Revocation")]
public class CryptoBackendTests
{
    [Theory]
    [InlineData(true, true, 1024)] [InlineData(true, false, 1024)]
    [InlineData(false, true, 1024)] [InlineData(false, false, 1024)]
    [InlineData(true, false, 1048577)] [InlineData(false, true, 1048577)]
    [InlineData(false, false, 1048577)]
    public async Task BackendsInteroperateWithRsaRecipientsAndStreamLargeMessages(bool nativeSender, bool nativeReceiver, int size)
    {
        using var rsa = RSA.Create(2048); using var recipientRsa = RSA.Create(2048);
        var sender = new WebKey(rsa); var recipient = new WebKey(recipientRsa);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, nativeSender).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, nativeReceiver).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), recipient);
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, nativeReceiver).Create(null);
        try
        {
            var bytes = RandomNumberGenerator.GetBytes(size);
            using var input = new MemoryStream(bytes); using var encrypted = await sealer.SealAsync(input, recipient);
            if (size > Settings.Default.InMemorySize) Assert.False(encrypted is MemoryStream);
            var validation = await verifier.VerifyAsync(encrypted, sender);
            Assert.Equal(ValidationStatus.Valid, validation.ValidationStatus);
            encrypted.Position = 0;
            var result = await receiver.UnsealAsync(encrypted, sender);
            using (result.UnsealedData) using (var clear = new MemoryStream())
            {
                result.UnsealedData.CopyTo(clear); Assert.Equal(bytes, clear.ToArray());
                Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                if (size > Settings.Default.InMemorySize) Assert.False(result.UnsealedData is MemoryStream);
            }
            Assert.True(input.CanRead); Assert.True(encrypted.CanRead);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); (verifier as IDisposable)?.Dispose(); }
    }

    [Fact]
    public void FlagIsCapturedPerInstanceAndFactoriesCanPinEitherBackend()
    {
        bool previous = Settings.Default.UseNativeCrypto;
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var factory = new DataSealerFactory(NullLoggerFactory.Instance);
        try
        {
            Settings.Default.UseNativeCrypto = false;
            var bouncy = factory.Create(Level.B_Level, sender);
            Settings.Default.UseNativeCrypto = true;
            var native = factory.Create(Level.B_Level, sender);
            var pinned = new DataSealerFactory(NullLoggerFactory.Instance, false).Create(Level.B_Level, sender);
            try
            {
                Assert.Equal("BouncyCastleTripleWrapper", bouncy.GetType().Name);
                Assert.Equal("TripleWrapper", native.GetType().Name);
                Assert.Equal(bouncy.GetType(), pinned.GetType());
#pragma warning disable CS0618
                Settings.Default.UseNativeRsaPss = false;
                Assert.False(Settings.Default.UseNativeCrypto);
                Settings.Default.UseNativeRsaPss = true;
                Assert.True(Settings.Default.UseNativeCrypto);
#pragma warning restore CS0618
            }
            finally { (bouncy as IDisposable)?.Dispose(); (native as IDisposable)?.Dispose(); (pinned as IDisposable)?.Dispose(); }
        }
        finally { Settings.Default.UseNativeCrypto = previous; }
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    public async Task RejectsChangedContentInEitherSignedLayer(bool native, bool changeInner)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        byte[] kek = RandomNumberGenerator.GetBytes(16), payload = RandomNumberGenerator.GetBytes(200);
        var secret = new SecretKey(new byte[] { 3 }, kek);
        var inner = new CmsSignedData(NativeRsaPssTests.BouncySign(payload, rsa, sender.Id));
        if (changeInner)
        {
            payload[0] ^= 1;
            var changed = new CmsSignedDataGenerator(); changed.AddSigners(inner.GetSignerInfos());
            inner = changed.Generate(new CmsProcessableByteArray(payload), true);
        }
        var envelope = new CmsEnvelopedDataGenerator(); envelope.AddKekRecipient("AES", new KeyParameter(kek), secret.Id);
        byte[] encrypted = envelope.Generate(new CmsProcessableByteArray(inner.GetEncoded()), CmsEnvelopedGenerator.Aes128Cbc).GetEncoded();
        byte[] outer = NativeRsaPssTests.BouncySign(encrypted, rsa, sender.Id);
        if (!changeInner)
        {
            // A fresh, valid envelope for the same plaintext changes its content encryption
            // key and IV. Retaining the old outer signer must fail the message-digest check.
            var changed = new CmsSignedDataGenerator(); changed.AddSigners(new CmsSignedData(outer).GetSignerInfos());
            encrypted = envelope.Generate(new CmsProcessableByteArray(inner.GetEncoded()), CmsEnvelopedGenerator.Aes128Cbc).GetEncoded();
            outer = changed.Generate(new CmsProcessableByteArray(encrypted), true).GetEncoded();
        }
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        try
        {
            using var input = new MemoryStream(outer); var result = await receiver.UnsealAsync(input, sender, secret);
            using (result.UnsealedData)
            {
                Assert.Equal(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
                Assert.Equal(ValidationStatus.Invalid, (changeInner ? result.SecurityInformation.InnerSignature : result.SecurityInformation.OuterSignature).ValidationStatus);
            }
        }
        finally { (receiver as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task LegacyRsaPssWithoutSignedAttributesStillVerifies(bool native)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().SetDirectSignature(true).Build(
            new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHRSAANDMGF1", Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(rsa).Private), sender.Id));
        byte[] message = generator.Generate(new CmsProcessableByteArray(new byte[32768]), true).GetEncoded();
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, native).Create(null);
        try
        {
            using var input = new MemoryStream(message);
            Assert.Equal(ValidationStatus.Valid, (await verifier.VerifyAsync(input, sender)).ValidationStatus);
        }
        finally { (verifier as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task CancellationStopsSealingAndNonSeekableInputsWork(bool native)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var secret = new SecretKey(new byte[] { 1 }, new byte[16]);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, native).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        try
        {
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            using var input = new MemoryStream(new byte[32]);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sealer.SealAsync(input, secret, cancelled.Token, Array.Empty<EncryptionToken>()));
            using var nonSeek = new NonSeekableStream(new byte[32768]);
            using var sealedData = await sealer.SealAsync(nonSeek, secret, Array.Empty<EncryptionToken>());
            using var encoded = new MemoryStream(); sealedData.CopyTo(encoded);
            using var receiverInput = new NonSeekableStream(encoded.ToArray());
            var result = await receiver.UnsealAsync(receiverInput, sender, secret);
            using (result.UnsealedData) Assert.Equal(32768, result.UnsealedData.Length);
            Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.True(nonSeek.CanRead); Assert.True(receiverInput.CanRead);
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }

    private sealed class NonSeekableStream : MemoryStream
    {
        internal NonSeekableStream(byte[] bytes) : base(bytes) { }
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    }
}
