using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Utils;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Egelke.EHealth.Etee.Crypto
{
    internal sealed class BouncyCastleTripleUnwrapper : TripleUnwrapper
    {
        private readonly BouncyCms.Keys bouncyKeys = new();
        internal BouncyCastleTripleUnwrapper(Level? level, ITimemarkProvider timemark, X509Certificate2Collection encryption, X509Certificate2Collection authentication, WebKey[] keys, ILogger<TripleUnwrapper> logger)
            : base(level, timemark, encryption, authentication, keys, logger) { }
        public override void Dispose() { base.Dispose(); bouncyKeys.Clear(); }

        protected override async Task<UnsealResult> UnsealCoreAsync(Stream data, WebKey sender, SecretKey secret)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            using var source = new BouncyCms.Input(data);
            var streams = BouncyCms.Streams(source.Stream);
            using var encrypted = streams.CreateNew();
            var outer = await VerifyAndCopyAsync(source.Stream, encrypted, sender, null, timemark).ConfigureAwait(false);
            encrypted.Position = 0;
            using var inner = streams.CreateNew();
            var encryption = await DecryptAsync(encrypted, inner, secret, outer.SigningTime ?? DateTime.UtcNow).ConfigureAwait(false);
            inner.Position = 0;
            var clear = streams.CreateNew();
            try
            {
                var signature = await VerifyAndCopyAsync(inner, clear, sender, outer, timemark).ConfigureAwait(false);
                clear.Position = 0;
                return new UnsealResult { UnsealedData = clear, SecurityInformation = new UnsealSecurityInformation { OuterSignature = outer, Encryption = encryption, InnerSignature = signature } };
            }
            catch { clear.Dispose(); throw; }
        }

        protected override async Task<SignatureSecurityInformation> VerifyMessageAsync(Stream data, WebKey sender, ITimemarkProvider provider)
        {
            RuntimeCompat.ThrowIfDisposed(disposed != 0, this);
            using var source = new BouncyCms.Input(data);
            return await VerifyAndCopyAsync(source.Stream, Stream.Null, sender, null, provider).ConfigureAwait(false);
        }

        private async Task<SignatureSecurityInformation> VerifyAndCopyAsync(Stream input, Stream output, WebKey sender, SignatureSecurityInformation outer, ITimemarkProvider provider)
        {
            long start = input.Position;
            BouncyCms.ValidateFrame(input);
            try
            {
                var parser = new CmsSignedDataParser(input);
                if (parser.SignedContentType.Id != CryptoEncoding.Data) throw new InvalidMessageException("Unexpected signed content type");
                OperationScope.Copy(parser.GetSignedContent().ContentStream, output);
                var metadata = BouncyCms.Metadata(parser);
                // Keep the parser's signer: it contains the payload digest calculated during the copy.
                var signers = parser.GetSignerInfos().GetSigners();
                if (signers.Count == 1 && signers.Single().SignedAttributes == null)
                {
                    // Legacy messages without signed attributes cannot use BC's streaming
                    // RSA-PSS verifier. Preserve their compatibility with buffered verification.
                    input.Position = start;
                    signers = new CmsSignedData(NativeCms.Read(input)).GetSignerInfos().GetSigners();
                }
                byte[] encodedMetadata = metadata.GetEncoded();
                return await VerifyCoreAsync(NativeCms.Decode(encodedMetadata), sender, outer, provider, (certificate, web) =>
                {
                    var signer = signers.Single();
                    var key = certificate != null ? DotNetUtilities.FromX509Certificate(certificate).GetPublicKey() : BouncyCms.PublicKey(web);
                    try
                    {
                        if (!signer.Verify(key)) throw new CryptographicException("Invalid CMS signature");
                    }
                    catch (CmsException error) { throw new CryptographicException("Invalid CMS signature", error); }
                }, NativeCms.LoadCertificates(NativeCms.CertificateSet(encodedMetadata))).ConfigureAwait(false);
            }
            catch (CmsException error) { throw new InvalidMessageException("Invalid CMS signed message", error); }
        }

        private async Task<SecurityInformation> DecryptAsync(Stream input, Stream output, SecretKey secret, DateTime date)
        {
            BouncyCms.ValidateFrame(input);
            var envelope = new CmsEnvelopedDataParser(input);
            if (!EteeActiveConfig.Unseal.EncryptionAlgorithms.Any(a => a.Value == envelope.EncryptionAlgOid))
                throw new InvalidMessageException("Unsupported content encryption algorithm");
            RecipientInformation selected = null;
            ICipherParameters privateKey = null;
            X509Certificate2 selectedCertificate = null;
            var result = new SecurityInformation();
            int keyBits = 0;
            foreach (var recipient in envelope.GetRecipientInfos().GetRecipients())
            {
                if (secret != null)
                {
                    if (recipient is KekRecipientInformation && secret.Id.AsSpan().SequenceEqual(recipient.RecipientID.KeyIdentifier))
                    {
                        string expectedWrap = secret.NativeKey.Length switch { 16 => "2.16.840.1.101.3.4.1.5", 24 => "2.16.840.1.101.3.4.1.25", 32 => "2.16.840.1.101.3.4.1.45", _ => throw new InvalidMessageException("Unsupported AES key size") };
                        if (recipient.KeyEncryptionAlgOid != expectedWrap) throw new InvalidMessageException("Unexpected KEK wrapping algorithm");
                        selected = recipient; privateKey = new KeyParameter(secret.NativeKey); keyBits = secret.NativeKey.Length * 8; result.SubjectId = secret.Id; break;
                    }
                    continue; // An explicitly supplied KEK must never fall back to certificate decryption.
                }
                if (!(recipient is KeyTransRecipientInformation)) continue;
                if (recipient.KeyEncryptionAlgOid != CryptoEncoding.Rsa) continue;
                var certificate = (encryptionCertificates ?? new X509Certificate2Collection()).Cast<X509Certificate2>()
                    .Where(c => c.HasPrivateKey && recipient.RecipientID.Match(DotNetUtilities.FromX509Certificate(c)) && PublicKeyCache.Get(c) is RSA)
                    .OrderByDescending(c => CryptoEncoding.ValidAt(c, date)).ThenByDescending(c => c.NotBefore).FirstOrDefault();
                if (certificate != null)
                {
                    if (certificate.IsBetter(selectedCertificate, date))
                    {
                        selected = recipient; selectedCertificate = certificate; privateKey = null;
                        result.SubjectId = CryptoEncoding.SubjectKeyIdentifier(certificate);
                    }
                    continue;
                }
                // BC 2.6 stores the DER OCTET STRING here, rather than its raw key identifier.
                byte[] encodedId = recipient.RecipientID.SubjectKeyIdentifier;
                byte[] id = encodedId == null ? null : Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(encodedId).GetOctets();
                var web = ownKeys.FirstOrDefault(w => id != null && w.Id.AsSpan().SequenceEqual(id));
                if (web != null && selected == null)
                {
                    selected = recipient; privateKey = bouncyKeys.Get(web); keyBits = web.NativeKey.KeySize; result.SubjectId = web.Id;
                }
            }
            if (selected == null) throw new InvalidMessageException("The message is not addressed to an available recipient");
            if (selectedCertificate != null) privateKey = bouncyKeys.Get(selectedCertificate);
            if (selectedCertificate != null)
                result.Subject = await selectedCertificate.VerifyAsync(date, new[] { 2, 3 }, EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey, authenticationCertificates, null, null).ConfigureAwait(false);
            else if (keyBits < (secret == null ? EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey : EteeActiveConfig.Unseal.MinimumEncryptionKeySize.SymmetricRecipientKey))
                result.securityViolations.Add(SecurityViolation.NotAllowedEncryptionKeySize);
            try
            {
                using var content = selected.GetContentStream(privateKey).ContentStream;
                OperationScope.Copy(content, output);
            }
            catch (CmsException error) { throw new InvalidMessageException("Invalid CMS envelope", error); }
            return result;
        }
    }
}
