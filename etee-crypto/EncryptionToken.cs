using System;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Utils;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>An eHealth ETK, represented with native CMS and X.509 APIs.</summary>
    public class EncryptionToken
    {
        private readonly SignedCms cms = new SignedCms();
        private readonly byte[] encoded;
        private readonly Lazy<X509Certificate2> certificate;
        public EncryptionToken(string data) : this(Convert.FromBase64String(data)) { }
        public EncryptionToken(byte[] data)
        {
            encoded = (byte[])data.Clone(); cms.Decode(encoded);
            certificate = new Lazy<X509Certificate2>(() => new X509Certificate2(cms.ContentInfo.Content));
        }
        /// <summary>Returns the cached certificate; callers must not dispose it.</summary>
        public X509Certificate2 ToCertificate() => certificate.Value;
        public byte[] GetEncoded() => (byte[])encoded.Clone();
        public string GetEncodedAsString() => Convert.ToBase64String(encoded);
        public CertificateSecurityInformation Verify() => Verify(true);
        public CertificateSecurityInformation Verify(bool checkRevocation) => VerifyAsync(checkRevocation).GetAwaiter().GetResult();
        public Task<CertificateSecurityInformation> VerifyAsync() => VerifyAsync(true);
        public async Task<CertificateSecurityInformation> VerifyAsync(bool checkRevocation)
        {
            var cert = ToCertificate();
            var result = await cert.VerifyAsync(DateTime.UtcNow, new[] { 2, 3 }, EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey,
                cms.Certificates, checkRevocation ? new List<CertificateRevocationList>() : null, checkRevocation ? new List<OcspResponse>() : null).ConfigureAwait(false);
            using var rsa = cert.GetRSAPublicKey(); if (rsa == null) result.securityViolations.Add(CertSecurityViolation.NotValidKeyType);
            return result;
        }
    }
}
