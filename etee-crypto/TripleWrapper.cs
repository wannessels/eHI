using System.Collections.Generic;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Etee.Crypto.Utils;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Etee.Crypto
{
    internal class TripleWrapper : IDataSealer, IDataCompleter, ITmaDataCompleter, IDisposable
    {
        protected readonly Level level;
        protected readonly WebKey ownWebKey;
        protected readonly X509Certificate2 authentication, signature;
        protected readonly RSASignaturePadding rsaSignaturePadding;
        private readonly ITimestampProvider timestampProvider;
        private readonly X509Certificate2Collection extraStore;
        private readonly ILogger<TripleWrapper> logger;
        private readonly ConcurrentDictionary<X509Certificate2, SigningKeyPool> keys = new();
        private readonly Lazy<SigningKeyPool> webKeyPool;
        protected int disposed;
        internal TripleWrapper(Level level, WebKey ownWebKey, ITimestampProvider timestampProvider, ILogger<TripleWrapper> logger = null, RSASignaturePadding rsaSignaturePadding = null)
            : this(level, null, null, timestampProvider, null, logger, rsaSignaturePadding) { this.ownWebKey = ownWebKey; }
        internal TripleWrapper(Level level, X509Certificate2 authentication, X509Certificate2 signature, ITimestampProvider timestampProvider, X509Certificate2Collection extraStore, ILogger<TripleWrapper> logger = null, RSASignaturePadding rsaSignaturePadding = null)
        {
            if (level == Level.L_Level || level == Level.A_level) throw new ArgumentException("Invalid sealing level", nameof(level));
            this.level = level; this.authentication = authentication; this.signature = signature ?? authentication;
            this.rsaSignaturePadding = rsaSignaturePadding ?? Settings.Default.RsaSignaturePadding;
            this.timestampProvider = timestampProvider; this.extraStore = extraStore; this.logger = logger;
            webKeyPool = new Lazy<SigningKeyPool>(() => SigningKeyPool.ForWebKey(this.ownWebKey.NativeKey, Settings.Default.SigningKeyHandles));
        }
        public virtual void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            foreach (var pool in keys.Values) pool.Dispose();
            keys.Clear();
            if (webKeyPool.IsValueCreated) webKeyPool.Value.Dispose();
        }
        private SigningKeyPool Pool(X509Certificate2 cert)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            if (cert == null) return webKeyPool.Value;
            return keys.GetOrAdd(cert, value => new SigningKeyPool(() =>
                (AsymmetricAlgorithm)value.GetRSAPrivateKey() ?? value.GetECDsaPrivateKey() ?? throw new CryptographicException("A native RSA or ECDSA private key is required"), Settings.Default.SigningKeyHandles));
        }
        public Stream Seal(Stream input, params EncryptionToken[] recipients) => SealAsync(input, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, params X509Certificate2[] recipients) => SealAsync(input, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, params WebKey[] recipients) => SealAsync(input, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, SecretKey key, params EncryptionToken[] recipients) => SealAsync(input, key, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, SecretKey key, EncryptionToken[] recipients, WebKey[] webKeys) => SealAsync(input, key, recipients, webKeys).GetAwaiter().GetResult();
        public Task<Stream> SealAsync(Stream input, params EncryptionToken[] recipients) => SealAsync(input, null, recipients, null);
        public Task<Stream> SealAsync(Stream input, params X509Certificate2[] recipients) => OperationPolicy.Default.RunAsync("seal", _ => SealCoreAsync(input, null, recipients, null));
        public Task<Stream> SealAsync(Stream input, params WebKey[] recipients) => SealAsync(input, null, null, recipients);
        public Task<Stream> SealAsync(Stream input, SecretKey key, params EncryptionToken[] recipients) => SealAsync(input, key, recipients, null);
        public Task<Stream> SealAsync(Stream input, SecretKey key, EncryptionToken[] recipients, WebKey[] webKeys)
            => OperationPolicy.Default.RunAsync("seal", _ => SealCoreAsync(input, key, recipients?.Select(t => t.ToCertificate()).ToArray(), webKeys));
        protected virtual async Task<Stream> SealCoreAsync(Stream input, SecretKey key, X509Certificate2[] recipients, WebKey[] webKeys)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            if (signature == null && ownWebKey == null) throw new InvalidOperationException("A signing certificate or WebKey is required");
            var result = new CryptoSpool(CryptoSpool.Remaining(input));
            try
            {
                using var outer = new NativeSigningWriter(result, authentication != null);
                using var encrypted = NativeEnvelope.OpenEncryption(outer, recipients, webKeys, key);
                using var inner = new NativeSigningWriter(encrypted.Content, signature != null);
                await OperationScope.CopyAsync(input, inner).ConfigureAwait(false);
                var innerDigest = await inner.CompleteContentAsync().ConfigureAwait(false);
                var innerMetadata = await SignDigestAsync(innerDigest, signature).ConfigureAwait(false);
                await CompleteCoreAsync(innerMetadata, signature, signature == authentication ? null : level & ~Level.T_Level).ConfigureAwait(false);
                inner.CompleteMetadata(innerMetadata);
                await encrypted.CompleteAsync().ConfigureAwait(false);
                var outerDigest = await outer.CompleteContentAsync().ConfigureAwait(false);
                SignedCms outerMetadata;
                for (int retry = 0; ; retry++)
                {
                    OperationScope.Cancellation.ThrowIfCancellationRequested();
                    try { outerMetadata = await SignDigestAsync(outerDigest, authentication).ConfigureAwait(false); break; }
                    catch (CryptographicException) when (retry < Settings.Default.SignRetries)
                    { await Task.Delay((int)Math.Pow(10, retry + 1), OperationScope.Cancellation).ConfigureAwait(false); }
                }
                await CompleteCoreAsync(outerMetadata, authentication, level).ConfigureAwait(false);
                outer.CompleteMetadata(outerMetadata);
                result.Position = 0; return result;
            }
            catch { result.Dispose(); throw; }
        }
        private async Task<SignedCms> SignDigestAsync(byte[] digest, X509Certificate2 certificate)
        {
            using var lease = await Pool(certificate).RentAsync(OperationScope.Cancellation).ConfigureAwait(false);
            return NativeStreamingCms.SignDigest(digest, certificate, lease.Key, ownWebKey?.Id, rsaSignaturePadding);
        }
        public Stream Complete(Stream data) => CompleteAsync(data).GetAwaiter().GetResult();
        public Stream Complete(Stream data, out TimemarkKey key)
        { var result = CompleteWithKeyAsync(data).GetAwaiter().GetResult(); key = result.TimemarkKey; return result.Value; }
        public async Task<Stream> CompleteAsync(Stream data) => (await CompleteWithKeyAsync(data).ConfigureAwait(false)).Value;
        Task<TimemarkedResult<Stream>> ITmaDataCompleter.CompleteAsync(Stream data) => CompleteWithKeyAsync(data);
        private Task<TimemarkedResult<Stream>> CompleteWithKeyAsync(Stream data) => OperationPolicy.Default.RunAsync("complete", _ => CompleteMessageAsync(data));
        protected virtual async Task<TimemarkedResult<Stream>> CompleteMessageAsync(Stream data)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            using var content = new CryptoSpool(CryptoSpool.Remaining(data));
            var detached = await NativeStreamingCms.ReadAsync(data, content).ConfigureAwait(false);
            var key = await CompleteCoreAsync(detached.Metadata, null, level, detached.Certificates).ConfigureAwait(false);
            content.Position = 0;
            var output = new CryptoSpool(content.Length);
            try { await NativeCms.Attach(detached.Metadata, content).WriteAsync(output).ConfigureAwait(false); output.Position = 0; return new TimemarkedResult<Stream>(output, key); }
            catch { output.Dispose(); throw; }
        }
        // Operates on signature metadata only. The streaming backend supplies detached CMS,
        // so chain building and unsigned-attribute updates never buffer the payload here.
        protected async Task<TimemarkKey> CompleteCoreAsync(SignedCms cms, X509Certificate2 provided, Level? requested, X509Certificate2Collection certificates = null)
        {
            var signer = NativeCms.SingleSigner(cms);
            certificates ??= cms.Certificates;
            var certificate = NativeCms.FindSigner(cms, certificates) ?? provided;
            var key = new TimemarkKey { Signer = certificate, SignerId = certificate != null ? CryptoEncoding.SubjectKeyIdentifier(certificate) : NativeCms.KeyId(signer), SigningTime = NativeCms.SigningTime(signer) ?? default, SignatureValue = signer.GetSignature() };
            if (key.SignerId == null) throw new InvalidMessageException("Missing signer identity");
            byte[] embeddedTimestamp = NativeCms.Attribute(signer.UnsignedAttributes, CryptoEncoding.TimestampAttribute);
            var timestamp = embeddedTimestamp?.ToTimeStampToken();
            if (key.SigningTime == default && timestamp != null) key.SigningTime = timestamp.TokenInfo.Timestamp.UtcDateTime;
            if (requested != null && certificate != null && certificates.Count <= 1)
            {
                var chain = certificate.BuildChain(key.SigningTime == default ? DateTime.UtcNow : key.SigningTime, extraStore);
                if (chain.ChainStatus.Any(status => status.Status != X509ChainStatusFlags.NoError)) throw new InvalidMessageException("Signer certificate chain failed validation");
                var embedded = new HashSet<string>(certificates.Cast<X509Certificate2>().Select(c => c.Thumbprint));
                foreach (var element in chain.ChainElements)
                {
                    if (embedded.Add(element.Certificate.Thumbprint)) cms.AddCertificate(element.Certificate);
                    element.Certificate.Dispose();
                }
                signer = NativeCms.SingleSigner(cms);
            }
            if (timestamp == null && (requested & Level.T_Level) == Level.T_Level && timestampProvider != null)
            {
                byte[] hash = CryptoEncoding.Hash(CryptoEncoding.Sha256, key.SignatureValue);
                byte[] bytes = timestampProvider is ITimestampProviderAsync asyncProvider
                    ? await asyncProvider.GetTimestampFromDocumentHashAsync(hash, "http://www.w3.org/2001/04/xmlenc#sha256").ConfigureAwait(false)
                    : timestampProvider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");
                timestamp = bytes.ToTimeStampToken();
                if (!timestamp.IsMatch(new MemoryStream(key.SignatureValue, false))) throw new InvalidMessageException("Timestamp does not match the signature");
                NativeCms.SetUnsigned(signer, CryptoEncoding.TimestampAttribute, bytes);
            }
            if ((requested & Level.L_Level) == Level.L_Level)
            {
                var evidence = NativeCms.RevocationValues(signer);
                if (certificate != null)
                {
                    var chain = await certificate.BuildChainAsync(key.SigningTime, cms.Certificates, evidence.Crls, evidence.Ocsps).ConfigureAwait(false);
                    if (chain.ChainStatus.Any(status => status.Status != X509ChainStatusFlags.NoError)) throw new InvalidMessageException("Signer revocation validation failed");
                    foreach (var element in chain.ChainElements) element.Certificate.Dispose();
                }
                if (timestamp != null)
                {
                    var validation = await timestamp.ValidateAsync(evidence.Crls, evidence.Ocsps).ConfigureAwait(false);
                    if (validation.TimestampStatus.Any(status => status.Status != X509ChainStatusFlags.NoError)) throw new InvalidMessageException("Timestamp validation failed");
                }
                NativeCms.SetUnsigned(signer, CryptoEncoding.RevocationAttribute, NativeCms.EncodeRevocationValues(evidence.Crls, evidence.Ocsps));
            }
            return key;
        }
    }
}
