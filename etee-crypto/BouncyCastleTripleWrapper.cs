using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Etee.Crypto.Utils;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Egelke.EHealth.Etee.Crypto
{
    internal sealed class BouncyCastleTripleWrapper : TripleWrapper
    {
        private readonly BouncyCms.Keys bouncyKeys = new();
        internal BouncyCastleTripleWrapper(Level level, WebKey key, ITimestampProvider timestamps, ILogger<TripleWrapper> logger, RSASignaturePadding rsaSignaturePadding = null)
            : base(level, key, timestamps, logger, rsaSignaturePadding) { }
        internal BouncyCastleTripleWrapper(Level level, X509Certificate2 authentication, X509Certificate2 signature, ITimestampProvider timestamps, X509Certificate2Collection extra, ILogger<TripleWrapper> logger, RSASignaturePadding rsaSignaturePadding = null)
            : base(level, authentication, signature, timestamps, extra, logger, rsaSignaturePadding) { }
        public override void Dispose() { base.Dispose(); bouncyKeys.Clear(); }

        protected override async Task<Stream> SealCoreAsync(Stream input, SecretKey key, X509Certificate2[] recipients, WebKey[] webKeys)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            if (signature == null && ownWebKey == null) throw new InvalidOperationException("A signing certificate or WebKey is required");
            using var source = new BouncyCms.Input(input);
            var streams = BouncyCms.Streams(source.Stream);
            using var inner = streams.CreateNew();
            using var encrypted = streams.CreateNew();
            await SignAndEmbedAsync(inner, source.Stream, signature, signature == authentication ? null : level & ~Level.T_Level).ConfigureAwait(false);
            inner.Position = 0;
            Encrypt(encrypted, inner, key, recipients, webKeys);
            var result = streams.CreateNew();
            try
            {
                for (int retry = 0; ; retry++)
                {
                    encrypted.Position = 0; result.SetLength(0); result.Position = 0;
                    try { await SignAndEmbedAsync(result, encrypted, authentication, level).ConfigureAwait(false); break; }
                    catch (CryptographicException) when (retry < Settings.Default.SignRetries)
                    { await Task.Delay((int)Math.Pow(10, retry + 1), OperationScope.Cancellation).ConfigureAwait(false); }
                }
                result.Position = 0; return result;
            }
            catch { result.Dispose(); throw; }
        }

        private async Task SignAndEmbedAsync(Stream output, Stream content, X509Certificate2 certificate, Level? requested)
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            var privateKey = certificate == null ? bouncyKeys.Get(ownWebKey) : bouncyKeys.Get(certificate);
            string algorithm = privateKey is RsaKeyParameters ? (rsaSignaturePadding == RSASignaturePadding.Pkcs1 ? "SHA256WITHRSA" : "SHA256WITHRSAANDMGF1") : privateKey is ECPrivateKeyParameters
                ? "SHA256WITHECDSA" : throw new NotSupportedException("RSA or ECDSA signing keys are required");
            var factory = new Asn1SignatureFactory(algorithm, privateKey);
            var builder = new SignerInfoGeneratorBuilder();
            var generator = new CmsSignedDataGenerator();
            generator.AddSignerInfoGenerator(certificate == null ? builder.Build(factory, ownWebKey.Id) : builder.Build(factory, DotNetUtilities.FromX509Certificate(certificate)));
            long start = content.Position;
            var detached = generator.Generate(new BouncyCms.Processable(content), false);
            var metadata = NativeCms.Decode(detached.GetEncoded());
            await CompleteCoreAsync(metadata, certificate, requested).ConfigureAwait(false);
            content.Position = start;
            BouncyCms.Embed(output, content, new CmsSignedData(metadata.Encode()));
        }

        private static void Encrypt(Stream output, Stream content, SecretKey secret, X509Certificate2[] certificates, WebKey[] webKeys)
        {
            var generator = new CmsEnvelopedDataStreamGenerator(); generator.SetBufferSize(BouncyCms.BufferSize);
            int recipients = 0;
            foreach (var cert in certificates ?? Array.Empty<X509Certificate2>())
            { generator.AddKeyTransRecipient(DotNetUtilities.FromX509Certificate(cert)); recipients++; }
            foreach (var web in webKeys ?? Array.Empty<WebKey>())
            {
                if (!(web.NativeKey is RSA)) throw new CryptographicException("Recipient WebKey must use RSA");
                generator.AddKeyTransRecipient(BouncyCms.PublicKey(web), web.Id); recipients++;
            }
            if (secret != null) { generator.AddKekRecipient("AES", new KeyParameter(secret.NativeKey), secret.Id); recipients++; }
            if (recipients == 0) throw new ArgumentException("At least one recipient is required");
            using var encrypted = generator.Open(output, CmsEnvelopedGenerator.Aes128Cbc);
            OperationScope.Copy(content, encrypted);
        }

        protected override async Task<TimemarkedResult<Stream>> CompleteMessageAsync(Stream data)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            using var source = new BouncyCms.Input(data);
            BouncyCms.ValidateFrame(source.Stream);
            var streams = BouncyCms.Streams(source.Stream);
            using var content = streams.CreateNew();
            var parser = new CmsSignedDataParser(source.Stream);
            if (parser.SignedContentType.Id != CryptoEncoding.Data) throw new InvalidMessageException("Unexpected signed content type");
            OperationScope.Copy(parser.GetSignedContent().ContentStream, content);
            var metadata = NativeCms.Decode(BouncyCms.Metadata(parser).GetEncoded());
            var key = await CompleteCoreAsync(metadata, null, level).ConfigureAwait(false);
            var result = streams.CreateNew();
            try
            {
                content.Position = 0; BouncyCms.Embed(result, content, new CmsSignedData(metadata.Encode()));
                result.Position = 0; return new TimemarkedResult<Stream>(result, key);
            }
            catch { result.Dispose(); throw; }
        }
    }
}
