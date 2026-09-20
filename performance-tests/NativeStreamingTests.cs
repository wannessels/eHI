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
using Xunit;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using RsassaPssParameters = Org.BouncyCastle.Asn1.Pkcs.RsassaPssParameters;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

[Collection("Revocation")]
public class NativeStreamingTests
{
    [Fact]
    public async Task LargeNonSeekablePayloadHasBoundedAllocationAndPreservesContent()
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa); var recipient = new SecretKey(new byte[] { 1 }, new byte[16]);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        long threshold = Settings.Default.InMemorySize; Settings.Default.InMemorySize = 64 * 1024;
        try
        {
            async Task RoundTrip(int size)
            {
                using var input = new GeneratedStream(size);
                using var encrypted = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
                var result = await receiver.UnsealAsync(encrypted, sender, recipient);
                using (result.UnsealedData)
                {
                    Assert.Equal(size, result.UnsealedData.Length);
                    Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                    using var expected = new GeneratedStream(size);
                    Assert.Equal(RuntimeCompat.HashStream(expected), RuntimeCompat.HashStream(result.UnsealedData));
                }
                Assert.True(input.CanRead); Assert.True(encrypted.CanRead);
            }
            await RoundTrip(1024 * 1024); // Warm crypto, temporary-file and buffer-pool paths.
            long before = GC.GetTotalAllocatedBytes(true);
            await RoundTrip(32 * 1024 * 1024);
            long allocated = GC.GetTotalAllocatedBytes(true) - before;
            Assert.True(allocated < 8 * 1024 * 1024, $"Large native round trip allocated {allocated} bytes");
        }
        finally { Settings.Default.InMemorySize = threshold; (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }

    [Fact]
    public async Task MetadataLimitAndMalformedLengthsFailWithoutLargeReads()
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, true).Create(null);
        int maximum = Settings.Default.MaximumNativeMetadataSize;
        try
        {
            Settings.Default.MaximumNativeMetadataSize = 128;
            // A 16 MiB OID in a sufficiently large outer frame: reject its declaration,
            // rather than allocating/reading the advertised metadata.
            using var advertised = new MemoryStream(new byte[] { 0x30, 0x84, 0x02, 0, 0, 0, 0x06, 0x84, 0x01, 0, 0, 0 });
            var limit = await Assert.ThrowsAsync<InvalidMessageException>(() => verifier.VerifyAsync(advertised, sender));
            Assert.Contains("metadata limit", limit.Message);
            using var oversizedChild = new MemoryStream(new byte[] { 0x30, 0x02, 0x06, 0x7F });
            await Assert.ThrowsAsync<InvalidMessageException>(() => verifier.VerifyAsync(oversizedChild, sender));
            Settings.Default.MaximumNativeMetadataSize = maximum;
            byte[] valid = NativeRsaPssTests.BouncySign(new byte[1024], rsa, sender.Id);
            foreach (int length in new[] { 0, 1, valid.Length / 2, valid.Length - 1 })
            {
                using var truncated = new MemoryStream(valid, 0, length, false);
                await Assert.ThrowsAnyAsync<Exception>(() => verifier.VerifyAsync(truncated, sender));
            }
            using var trailing = new MemoryStream(valid.Concat(new byte[] { 0 }).ToArray());
            await Assert.ThrowsAsync<InvalidMessageException>(() => verifier.VerifyAsync(trailing, sender));
        }
        finally { Settings.Default.MaximumNativeMetadataSize = maximum; (verifier as IDisposable)?.Dispose(); }
    }

    [Fact]
    public async Task NativeCancellationInterruptsSpoolingAndLeavesCallerInputOpen()
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        using var cancellation = new CancellationTokenSource();
        using var input = new GeneratedStream(32 * 1024 * 1024, cancellation);
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sealer.SealAsync(input, new SecretKey(new byte[] { 1 }, new byte[16]), cancellation.Token, Array.Empty<EncryptionToken>()));
            Assert.True(input.CanRead); Assert.True(input.BytesRead < 32 * 1024 * 1024);
        }
        finally { (sealer as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData("SHA512WITHRSAANDMGF1")]
    [InlineData("SHA512WITHRSA")]
    [InlineData("SHA256WITHRSA")]
    public async Task NativeStreamingVerifiesSupportedLegacyAlgorithms(string algorithm)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory(algorithm, DotNetUtilities.GetRsaKeyPair(rsa).Private), sender.Id));
        using var input = new MemoryStream(generator.Generate(new CmsProcessableByteArray(new byte[2000]), true).GetEncoded());
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, true).Create(null);
        try { Assert.Equal(ValidationStatus.Valid, (await verifier.VerifyAsync(input, sender)).ValidationStatus); }
        finally { (verifier as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task NativeVerifierBindsRawPssParametersAndSignedContentType(bool badContentType)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().SetDirectSignature(!badContentType)
            .Build(new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", DotNetUtilities.GetRsaKeyPair(rsa).Private), sender.Id));
        var contentInfo = ContentInfo.GetInstance(generator.Generate(new CmsProcessableByteArray(new byte[2000]), true).GetEncoded());
        var signed = SignedData.GetInstance(contentInfo.Content); var signer = SignerInfo.GetInstance(signed.SignerInfos[0]);
        var attributes = signer.SignedAttrs; var algorithm = signer.SignatureAlgorithm; var signature = signer.Signature;
        if (badContentType)
        {
            attributes = new DerSet(attributes.Cast<Asn1Encodable>().Select(value =>
            {
                var attribute = Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(value);
                return attribute.AttrType.Equals(CmsAttributes.ContentType)
                    ? new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.ContentType, new DerSet(new DerObjectIdentifier("1.2.3.4"))) : value;
            }).ToArray());
            // A cryptographically valid signature over incorrect attributes must still fail.
            signature = new DerOctetString(rsa.SignData(attributes.GetEncoded("DER"), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        else
        {
            var parameters = RsassaPssParameters.GetInstance(algorithm.Parameters);
            algorithm = new AlgorithmIdentifier(algorithm.Algorithm,
                new RsassaPssParameters(parameters.HashAlgorithm, parameters.MaskGenAlgorithm, new DerInteger(20), parameters.TrailerField));
        }
        var changed = new SignerInfo(signer.SignerID, signer.DigestAlgorithm, attributes, algorithm, signature, signer.UnsignedAttrs);
        var message = new ContentInfo(contentInfo.ContentType, new SignedData(signed.DigestAlgorithms, signed.EncapContentInfo, signed.Certificates, signed.CRLs, new DerSet(changed)));
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, true).Create(null);
        try
        {
            using var input = new MemoryStream(message.GetEncoded());
            Assert.Equal(ValidationStatus.Invalid, (await verifier.VerifyAsync(input, sender)).ValidationStatus);
        }
        finally { (verifier as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData(2)] [InlineData(40)]
    public async Task NativeBerPayloadSupportsChunksAndRejectsExcessiveNesting(int depth)
    {
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        byte[] bytes = RandomNumberGenerator.GetBytes(1234);
        var ci = ContentInfo.GetInstance(NativeRsaPssTests.BouncySign(bytes, rsa, sender.Id));
        var signed = SignedData.GetInstance(ci.Content);
        Asn1OctetString payload = new BerOctetString(new Asn1OctetString[] { new DerOctetString(bytes.AsSpan(0, 500).ToArray()), new DerOctetString(bytes.AsSpan(500).ToArray()) });
        for (int i = 0; i < depth; i++) payload = new BerOctetString(new[] { payload });
        var wrapped = new ContentInfo(ci.ContentType, new SignedData(signed.DigestAlgorithms, new ContentInfo(signed.EncapContentInfo.ContentType, payload), signed.Certificates, signed.CRLs, signed.SignerInfos));
        var verifier = new DataVerifierFactory(NullLoggerFactory.Instance, true).Create(null);
        try
        {
            using var input = new MemoryStream(wrapped.GetEncoded());
            if (depth < 32) Assert.Equal(ValidationStatus.Valid, (await verifier.VerifyAsync(input, sender)).ValidationStatus);
            else Assert.Contains("nesting limit", (await Assert.ThrowsAsync<InvalidMessageException>(() => verifier.VerifyAsync(input, sender))).Message);
        }
        finally { (verifier as IDisposable)?.Dispose(); }
    }

    private sealed class GeneratedStream : Stream
    {
        private readonly long length; private readonly CancellationTokenSource cancellation;
        private bool disposed;
        internal long BytesRead { get; private set; }
        internal GeneratedStream(long length, CancellationTokenSource cancellation = null) { this.length = length; this.cancellation = cancellation; }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            RuntimeCompat.ThrowIfDisposed(disposed, this);
            int count = (int)Math.Min(buffer.Length, length - BytesRead);
            for (int i = 0; i < count; i++) buffer[i] = (byte)((BytesRead + i) % 251);
            BytesRead += count;
            if (BytesRead >= 1024 * 1024) cancellation?.Cancel();
            return count;
        }
        public override bool CanRead => !disposed; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { } public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException(); public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { disposed = true; base.Dispose(disposing); }
    }
}
