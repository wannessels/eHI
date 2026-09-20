using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Etee.Crypto.Utils;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Etee.Crypto
{
    internal class TripleUnwrapper : IDataUnsealer, IDataVerifier, ITmaDataVerifier, IDisposable
    {
        protected readonly Level? level;
        protected readonly ITimemarkProvider timemark;
        protected readonly X509Certificate2Collection encryptionCertificates, authenticationCertificates;
        protected readonly WebKey[] ownKeys;
        protected int disposed;
        private readonly ILogger<TripleUnwrapper> logger;
        internal TripleUnwrapper(Level? level, ITimemarkProvider timemarkauthority, X509Certificate2Collection encCerts, X509Certificate2Collection authCertStore, WebKey[] ownWebKeys, ILogger<TripleUnwrapper> logger = null)
        {
            if (level == Level.L_Level || level == Level.A_level) throw new ArgumentException("Invalid unsealing level", nameof(level));
            this.level = level; timemark = timemarkauthority; encryptionCertificates = encCerts; authenticationCertificates = authCertStore;
            ownKeys = ownWebKeys ?? Array.Empty<WebKey>(); this.logger = logger;
        }
        public virtual void Dispose()
        {
            if (System.Threading.Interlocked.Exchange(ref disposed, 1) == 0 && authenticationCertificates != null)
                X509CertificateHelper.DisposeAll(authenticationCertificates);
        }
        public UnsealResult Unseal(Stream data) => UnsealAsync(data).GetAwaiter().GetResult();
        public UnsealResult Unseal(Stream data, WebKey sender) => UnsealAsync(data, sender).GetAwaiter().GetResult();
        public UnsealResult Unseal(Stream data, SecretKey key) => UnsealAsync(data, key).GetAwaiter().GetResult();
        public UnsealResult Unseal(Stream data, WebKey sender, SecretKey key) => UnsealAsync(data, sender, key).GetAwaiter().GetResult();
        public Task<UnsealResult> UnsealAsync(Stream data) => UnsealAsync(data, null, null);
        public Task<UnsealResult> UnsealAsync(Stream data, WebKey sender) => UnsealAsync(data, sender, null);
        public Task<UnsealResult> UnsealAsync(Stream data, SecretKey key) => UnsealAsync(data, null, key);
        public Task<UnsealResult> UnsealAsync(Stream data, WebKey sender, SecretKey key) => OperationPolicy.Default.RunAsync(_ => UnsealCoreAsync(data, sender, key));
        protected virtual async Task<UnsealResult> UnsealCoreAsync(Stream data, WebKey sender, SecretKey key)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            var outer = NativeCms.Decode(NativeCms.Read(data));
            var outerStatus = await VerifyCoreAsync(outer, sender, null, timemark).ConfigureAwait(false);
            var encrypted = NativeEnvelope.Decrypt(outer.ContentInfo.Content, encryptionCertificates, ownKeys, key, outerStatus.SigningTime ?? DateTime.UtcNow);
            var encryptionStatus = new SecurityInformation { SubjectId = encrypted.KeyId };
            if (encrypted.Certificate != null)
                encryptionStatus.Subject = await encrypted.Certificate.VerifyAsync(outerStatus.SigningTime ?? DateTime.UtcNow, new[] { 2, 3 }, EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey, authenticationCertificates, null, null).ConfigureAwait(false);
            else if (encrypted.KeySize < (key != null ? EteeActiveConfig.Unseal.MinimumEncryptionKeySize.SymmetricRecipientKey : EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey))
                encryptionStatus.securityViolations.Add(SecurityViolation.NotAllowedEncryptionKeySize);
            var inner = NativeCms.Decode(encrypted.Content);
            var innerStatus = await VerifyCoreAsync(inner, sender, outerStatus, timemark).ConfigureAwait(false);
            Stream clear = inner.ContentInfo.Content.Length <= Settings.Default.InMemorySize ? new MemoryStream(inner.ContentInfo.Content, false) : new TempFileStreamFactory().CreateNew();
            try
            {
                if (!(clear is MemoryStream)) { using var source = new MemoryStream(inner.ContentInfo.Content, false); OperationScope.Copy(source, clear); clear.Position = 0; }
                return new UnsealResult { UnsealedData = clear, SecurityInformation = new UnsealSecurityInformation { OuterSignature = outerStatus, Encryption = encryptionStatus, InnerSignature = innerStatus } };
            }
            catch { clear.Dispose(); throw; }
        }
        public SignatureSecurityInformation Verify(Stream data) => VerifyAsync(data).GetAwaiter().GetResult();
        public SignatureSecurityInformation Verify(Stream data, WebKey sender) => VerifyAsync(data, sender).GetAwaiter().GetResult();
        public Task<SignatureSecurityInformation> VerifyAsync(Stream data) => VerifyAsync(data, (WebKey)null);
        public Task<SignatureSecurityInformation> VerifyAsync(Stream data, WebKey sender) => VerifyAsync(data, sender, timemark);
        private Task<SignatureSecurityInformation> VerifyAsync(Stream data, WebKey sender, ITimemarkProvider provider)
            => OperationPolicy.Default.RunAsync(_ => VerifyMessageAsync(data, sender, provider));
        protected virtual Task<SignatureSecurityInformation> VerifyMessageAsync(Stream data, WebKey sender, ITimemarkProvider provider)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            return VerifyCoreAsync(NativeCms.Decode(NativeCms.Read(data)), sender, null, provider);
        }
        public SignatureSecurityInformation Verify(Stream data, DateTime date) => VerifyAsync(data, date).GetAwaiter().GetResult();
        public Task<SignatureSecurityInformation> VerifyAsync(Stream data, DateTime date) => VerifyAsync(data, null, new FixedTimemarkProvider(date));
        public SignatureSecurityInformation Verify(Stream data, out TimemarkKey key) => Verify(data, null, out key);
        public SignatureSecurityInformation Verify(Stream data, WebKey sender, out TimemarkKey key)
        { var result = VerifyWithKeyAsync(data, sender, timemark).GetAwaiter().GetResult(); key = result.TimemarkKey; return result.Value; }
        public SignatureSecurityInformation Verify(Stream data, DateTime date, out TimemarkKey key)
        { var result = VerifyWithKeyAsync(data, null, new FixedTimemarkProvider(date)).GetAwaiter().GetResult(); key = result.TimemarkKey; return result.Value; }
        Task<TimemarkedResult<SignatureSecurityInformation>> ITmaDataVerifier.VerifyAsync(Stream data, DateTime date) => VerifyWithKeyAsync(data, null, new FixedTimemarkProvider(date));
        private async Task<TimemarkedResult<SignatureSecurityInformation>> VerifyWithKeyAsync(Stream data, WebKey sender, ITimemarkProvider provider)
        {
            var result = await VerifyAsync(data, sender, provider).ConfigureAwait(false);
            if (result.SigningTime == null) throw new InvalidMessageException("Time-mark keys require an embedded signing time");
            return new TimemarkedResult<SignatureSecurityInformation>(result, new TimemarkKey { Signer = result.Signer, SignerId = result.SignerId, SigningTime = result.SigningTime.Value, SignatureValue = result.SignatureValue });
        }
        protected async Task<SignatureSecurityInformation> VerifyCoreAsync(SignedCms cms, WebKey sender, SignatureSecurityInformation outer, ITimemarkProvider provider,
            Action<X509Certificate2, WebKey> verifySignature = null)
        {
            var result = new SignatureSecurityInformation();
            if (cms.SignerInfos.Count == 0) { result.securityViolations.Add(SecurityViolation.NotSigned); return result; }
            var signer = NativeCms.SingleSigner(cms);
            if (!EteeActiveConfig.Unseal.SignatureAlgorithms.Any(a => a.DigestAlgorithm.Value == signer.DigestAlgorithm.Value && a.EncryptionAlgorithm.Value == signer.SignatureAlgorithm.Value))
                result.securityViolations.Add(SecurityViolation.NotAllowedSignatureDigestAlgorithm);
            var certificate = NativeCms.FindSigner(cms);
            byte[] ski = NativeCms.KeyId(signer);
            if (cms.Certificates.Count > 0 && certificate == null) { result.securityViolations.Add(SecurityViolation.NotFoundSigner); return result; }
            if (outer != null && certificate != null)
            {
                var previous = outer.Signer;
                if (previous == null) result.securityViolations.Add(SecurityViolation.SubjectDoesNotMachEnvelopingSubject);
                else
                {
                    var previousIds = CryptoEncoding.NameValues(previous.SubjectName, "2.5.4.5"); var ids = CryptoEncoding.NameValues(certificate.SubjectName, "2.5.4.5");
                    if (previousIds.Length != 1 || ids.Length != 1 || previousIds[0] != ids[0] || !CryptoEncoding.NamesEqual(previous.IssuerName.RawData, certificate.IssuerName.RawData))
                        result.securityViolations.Add(SecurityViolation.SubjectDoesNotMachEnvelopingSubject);
                }
            }
            if (certificate == null && outer?.Signer != null)
            { certificate = outer.Signer; result.Subject = outer.Subject; result.SubjectId = outer.SignerId; }
            result.SignatureValue = signer.GetSignature();
            try
            {
                if (certificate != null)
                {
                    if (verifySignature != null) verifySignature(certificate, null);
                    else signer.CheckSignature(new X509Certificate2Collection(certificate), true);
                }
                else
                {
                    if (sender == null || ski == null || !ski.AsSpan().SequenceEqual(sender.Id)) throw new ArgumentException("The sender WebKey ID does not match", nameof(sender));
                    if (outer != null && !ski.AsSpan().SequenceEqual(outer.SignerId)) result.securityViolations.Add(SecurityViolation.SubjectDoesNotMachEnvelopingSubject);
                    result.SubjectId = ski;
                    if (verifySignature != null) verifySignature(null, sender);
                    else
                    {
                        using var carrier = NativeCms.KeyCarrier(sender.NativeKey, sender.Id);
                        signer.CheckSignature(new X509Certificate2Collection(carrier), true);
                    }
                    if (!CertVerifier.VerifyKeySize(sender.NativeKey, EteeActiveConfig.Unseal.MinimumSignatureKeySize)) result.securityViolations.Add(SecurityViolation.UntrustedSubject);
                }
            }
            catch (CryptographicException) { result.securityViolations.Add(SecurityViolation.NotSignatureValid); }
            result.IsNonRepudiatable = certificate != null && CryptoEncoding.HasKeyUsage(certificate, 1);
            result.SigningTime = NativeCms.SigningTime(signer);
            DateTime signingTime = result.SigningTime ?? DateTime.UtcNow;
            var evidence = level == null ? (null, null) : NativeCms.RevocationValues(signer);
            if ((level & Level.T_Level) == Level.T_Level && outer == null)
            {
                DateTime validatedTime;
                byte[] encodedTimestamp = NativeCms.Attribute(signer.UnsignedAttributes, CryptoEncoding.TimestampAttribute);
                if (encodedTimestamp != null)
                {
                    var timestamp = encodedTimestamp.ToTimeStampToken();
                    if (!timestamp.IsMatch(new MemoryStream(result.SignatureValue, false))) result.securityViolations.Add(SecurityViolation.InvalidTimestamp);
                    var validation = await timestamp.ValidateAsync(evidence.Item1, evidence.Item2, (level & Level.A_level) == Level.A_level ? DateTime.UtcNow : null).ConfigureAwait(false);
                    if (validation.TimestampStatus.Any(s => s.Status != X509ChainStatusFlags.NoError)) result.securityViolations.Add(SecurityViolation.InvalidTimestamp);
                    result.TimestampRenewalTime = validation.RenewalTime; validatedTime = validation.Time;
                    if (!result.SigningTime.HasValue) signingTime = validatedTime;
                }
                else
                {
                    if (provider == null || certificate == null || !result.SigningTime.HasValue) throw new InvalidMessageException("A timestamp or certificate-based time-mark provider is required");
                    validatedTime = provider is ITimemarkProviderAsync asyncProvider
                        ? await asyncProvider.GetTimemarkAsync(certificate, signingTime, result.SignatureValue).ConfigureAwait(false)
                        : provider.GetTimemark(certificate, signingTime, result.SignatureValue);
                    validatedTime = validatedTime.ToUniversalTime();
                }
                if (validatedTime > signingTime + EteeActiveConfig.ClockSkewness + Settings.Default.TimestampGracePeriod || validatedTime < signingTime - EteeActiveConfig.ClockSkewness)
                    result.securityViolations.Add(SecurityViolation.SealingTimeInvalid);
            }
            if (result.Subject == null && certificate != null)
            {
                result.Subject = await certificate.VerifyAsync(signingTime, outer == null ? new[] { 0 } : Array.Empty<int>(), EteeActiveConfig.Unseal.MinimumSignatureKeySize, cms.Certificates, evidence.Item1, evidence.Item2).ConfigureAwait(false);
                result.SubjectId = CryptoEncoding.SubjectKeyIdentifier(certificate);
            }
            return result;
        }
    }
}
