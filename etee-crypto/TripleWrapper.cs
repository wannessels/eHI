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
        private readonly Level level;
        private readonly WebKey ownWebKey;
        private readonly X509Certificate2 authentication, signature;
        private readonly ITimestampProvider timestampProvider;
        private readonly X509Certificate2Collection extraStore;
        private readonly ILogger<TripleWrapper> logger;
        private readonly ConcurrentDictionary<X509Certificate2, Lazy<AsymmetricAlgorithm>> keys = new();
        private int disposed;
        internal TripleWrapper(Level level, WebKey ownWebKey, ITimestampProvider timestampProvider, ILogger<TripleWrapper> logger = null)
            : this(level, null, null, timestampProvider, null, logger) { this.ownWebKey = ownWebKey; }
        internal TripleWrapper(Level level, X509Certificate2 authentication, X509Certificate2 signature, ITimestampProvider timestampProvider, X509Certificate2Collection extraStore, ILogger<TripleWrapper> logger = null)
        {
            if (level == Level.L_Level || level == Level.A_level) throw new ArgumentException("Invalid sealing level", nameof(level));
            this.level = level; this.authentication = authentication; this.signature = signature ?? authentication;
            this.timestampProvider = timestampProvider; this.extraStore = extraStore; this.logger = logger;
        }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            foreach (var key in keys.Values) if (key.IsValueCreated) key.Value.Dispose();
            keys.Clear();
        }
        private AsymmetricAlgorithm Key(X509Certificate2 cert)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            return keys.GetOrAdd(cert, value => new Lazy<AsymmetricAlgorithm>(() =>
                (AsymmetricAlgorithm)value.GetRSAPrivateKey() ?? value.GetECDsaPrivateKey() ?? throw new CryptographicException("A native RSA or ECDSA private key is required"))).Value;
        }
        public Stream Seal(Stream input, params EncryptionToken[] recipients) => SealAsync(input, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, params X509Certificate2[] recipients) => SealAsync(input, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, params WebKey[] recipients) => SealAsync(input, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, SecretKey key, params EncryptionToken[] recipients) => SealAsync(input, key, recipients).GetAwaiter().GetResult();
        public Stream Seal(Stream input, SecretKey key, EncryptionToken[] recipients, WebKey[] webKeys) => SealAsync(input, key, recipients, webKeys).GetAwaiter().GetResult();
        public Task<Stream> SealAsync(Stream input, params EncryptionToken[] recipients) => SealAsync(input, null, recipients, null);
        public Task<Stream> SealAsync(Stream input, params X509Certificate2[] recipients) => OperationPolicy.Default.RunAsync(_ => SealCoreAsync(input, null, recipients, null));
        public Task<Stream> SealAsync(Stream input, params WebKey[] recipients) => SealAsync(input, null, null, recipients);
        public Task<Stream> SealAsync(Stream input, SecretKey key, params EncryptionToken[] recipients) => SealAsync(input, key, recipients, null);
        public Task<Stream> SealAsync(Stream input, SecretKey key, EncryptionToken[] recipients, WebKey[] webKeys)
            => OperationPolicy.Default.RunAsync(_ => SealCoreAsync(input, key, recipients?.Select(t => t.ToCertificate()).ToArray(), webKeys));
        private async Task<Stream> SealCoreAsync(Stream input, SecretKey key, X509Certificate2[] recipients, WebKey[] webKeys)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            if (signature == null && ownWebKey == null) throw new InvalidOperationException("A signing certificate or WebKey is required");
            byte[] clear = NativeCms.Read(input);
            var inner = Sign(clear, signature);
            await CompleteCoreAsync(inner, signature, signature == authentication ? null : level & ~Level.T_Level).ConfigureAwait(false);
            byte[] encrypted = NativeEnvelope.Encrypt(inner.Encode(), recipients, webKeys, key);
            SignedCms outer = null;
            for (int retry = 0; ; retry++)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                try { outer = Sign(encrypted, authentication); break; }
                catch (CryptographicException) when (retry < Settings.Default.SignRetries)
                { await Task.Delay((int)Math.Pow(10, retry + 1), OperationScope.Cancellation).ConfigureAwait(false); }
            }
            await CompleteCoreAsync(outer, authentication, level).ConfigureAwait(false);
            return ToStream(outer.Encode());
        }
        private SignedCms Sign(byte[] data, X509Certificate2 certificate)
            => certificate != null ? NativeCms.Sign(data, certificate, Key(certificate)) : NativeCms.Sign(data, null, ownWebKey.NativeKey, ownWebKey.Id);
        protected void SignDetached(Stream signed, Stream unsigned, X509Certificate2 selectedCert)
        {
            var cms = new SignedCms(new ContentInfo(NativeCms.Read(unsigned)), true);
            var key = Key(selectedCert);
            var signer = new CmsSigner(selectedCert) { PrivateKey = key, DigestAlgorithm = new Oid(CryptoEncoding.Sha256), IncludeOption = X509IncludeOption.None };
            if (key is RSA) signer.SignaturePadding = RSASignaturePadding.Pss;
            signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            lock (key) cms.ComputeSignature(signer, true);
            byte[] bytes = cms.Encode(); signed.Write(bytes, 0, bytes.Length);
        }
        public Stream Complete(Stream data) => CompleteAsync(data).GetAwaiter().GetResult();
        public Stream Complete(Stream data, out TimemarkKey key)
        { var result = CompleteWithKeyAsync(data).GetAwaiter().GetResult(); key = result.TimemarkKey; return result.Value; }
        public async Task<Stream> CompleteAsync(Stream data) => (await CompleteWithKeyAsync(data).ConfigureAwait(false)).Value;
        Task<TimemarkedResult<Stream>> ITmaDataCompleter.CompleteAsync(Stream data) => CompleteWithKeyAsync(data);
        private Task<TimemarkedResult<Stream>> CompleteWithKeyAsync(Stream data) => OperationPolicy.Default.RunAsync(async _ =>
        {
            var cms = NativeCms.Decode(NativeCms.Read(data));
            var key = await CompleteCoreAsync(cms, null, level).ConfigureAwait(false);
            return new TimemarkedResult<Stream>(ToStream(cms.Encode()), key);
        });
        private async Task<TimemarkKey> CompleteCoreAsync(SignedCms cms, X509Certificate2 provided, Level? requested)
        {
            var signer = NativeCms.SingleSigner(cms);
            var certificate = NativeCms.FindSigner(cms) ?? provided;
            var key = new TimemarkKey { Signer = certificate, SignerId = certificate != null ? CryptoEncoding.SubjectKeyIdentifier(certificate) : NativeCms.KeyId(signer), SigningTime = NativeCms.SigningTime(signer) ?? default, SignatureValue = signer.GetSignature() };
            if (key.SignerId == null) throw new InvalidMessageException("Missing signer identity");
            byte[] embeddedTimestamp = NativeCms.Attribute(signer.UnsignedAttributes, CryptoEncoding.TimestampAttribute);
            var timestamp = embeddedTimestamp?.ToTimeStampToken();
            if (key.SigningTime == default && timestamp != null) key.SigningTime = timestamp.TokenInfo.Timestamp.UtcDateTime;
            if (requested != null && certificate != null && cms.Certificates.Count <= 1)
            {
                var chain = certificate.BuildChain(key.SigningTime == default ? DateTime.UtcNow : key.SigningTime, extraStore);
                if (chain.ChainStatus.Any(status => status.Status != X509ChainStatusFlags.NoError)) throw new InvalidMessageException("Signer certificate chain failed validation");
                foreach (var element in chain.ChainElements)
                {
                    if (!cms.Certificates.Contains(element.Certificate)) cms.AddCertificate(element.Certificate);
                    element.Certificate.Dispose();
                }
                signer = NativeCms.SingleSigner(cms);
            }
            if (timestamp == null && (requested & Level.T_Level) == Level.T_Level && timestampProvider != null)
            {
                byte[] hash = SHA256.HashData(key.SignatureValue);
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
        private static Stream ToStream(byte[] value)
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            if (value.Length <= Settings.Default.InMemorySize) return new MemoryStream(value, false);
            var stream = new TempFileStreamFactory().CreateNew();
            try { using var input = new MemoryStream(value, false); OperationScope.Copy(input, stream); stream.Position = 0; return stream; }
            catch { stream.Dispose(); throw; }
        }
    }
}
