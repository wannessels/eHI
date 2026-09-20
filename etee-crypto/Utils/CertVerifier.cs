using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Status;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal static class CertVerifier
    {
        internal static byte[] GetSubjectKeyIdentifier(this X509Certificate2 cert) => CryptoEncoding.SubjectKeyIdentifier(cert);
        internal static CertificateSecurityInformation Verify(this X509Certificate2 cert, DateTime time, int[] usages, int minimum, X509Certificate2Collection extra, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps)
            => cert.VerifyAsync(time, usages, minimum, extra, crls, ocsps).ConfigureAwait(false).GetAwaiter().GetResult();
        internal static async Task<CertificateSecurityInformation> VerifyAsync(this X509Certificate2 cert, DateTime time, int[] usages, int minimum, X509Certificate2Collection extra, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps)
        {
            var result = new CertificateSecurityInformation { Certificate = new X509Certificate2(cert) };
            if (!VerifyKeySize(cert, minimum)) result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);
            if (usages.Any(bit => !CryptoEncoding.HasKeyUsage(cert, bit))) result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
            var derivedIssuer = ValidateAndGetDerivedIssuer(cert, extra);
            var chainSubject = derivedIssuer ?? cert;
            CertificateSecurityInformation destination = result;
            if (derivedIssuer != null)
            {
                if (!CryptoEncoding.ValidAt(cert, time)) result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
                destination = new CertificateSecurityInformation(); result.IssuerInfo = destination;
                if (!VerifyKeySize(derivedIssuer, minimum)) destination.securityViolations.Add(CertSecurityViolation.NotValidKeySize);
                if (!CryptoEncoding.HasKeyUsage(derivedIssuer, 0) || !CryptoEncoding.HasKeyUsage(derivedIssuer, 1)) destination.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
            }
            Chain chain = crls != null || ocsps != null
                ? await chainSubject.BuildChainAsync(time, extra, crls ?? new List<CertificateRevocationList>(), ocsps ?? new List<OcspResponse>()).ConfigureAwait(false)
                : chainSubject.BuildChain(time, extra);
            foreach (var element in chain.ChainElements)
            {
                destination.Certificate?.Dispose(); destination.Certificate = element.Certificate;
                foreach (var status in element.ChainElementStatus.Where(s => s.Status != X509ChainStatusFlags.NoError))
                {
                    if (Enum.TryParse<CertSecurityViolation>(status.Status.ToString(), out var violation)) destination.securityViolations.Add(violation);
                    else destination.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
                }
                if (!ReferenceEquals(element, chain.ChainElements.Last())) { destination.IssuerInfo = new CertificateSecurityInformation(); destination = destination.IssuerInfo; }
            }
            if (chain.ChainStatus.Any(s => s.Status == X509ChainStatusFlags.PartialChain)) result.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
            return result;
        }
        internal static X509Certificate2 ValidateAndGetDerivedIssuer(X509Certificate2 cert, X509Certificate2Collection candidates)
        {
            if (!CryptoEncoding.NamesEqual(cert.IssuerName.RawData, cert.SubjectName.RawData) || CryptoEncoding.VerifyCertificate(cert, cert)) return null;
            X509Certificate2 best = null;
            foreach (var candidate in (candidates ?? new X509Certificate2Collection()).Cast<X509Certificate2>())
            {
                if (!CryptoEncoding.NamesEqual(cert.IssuerName.RawData, candidate.SubjectName.RawData)) continue;
                try { if (CryptoEncoding.VerifyCertificate(cert, candidate) && candidate.IsBetter(best, cert.NotBefore.ToUniversalTime())) best = candidate; }
                catch (CryptographicException) { }
            }
            return best;
        }
        internal static bool IsBetter(this X509Certificate2 self, X509Certificate2 other, DateTime time)
            => other == null || CryptoEncoding.ValidAt(self, time) && (!CryptoEncoding.ValidAt(other, time) || self.NotBefore > other.NotBefore);
        internal static bool VerifyKeySize(X509Certificate2 cert, int minimum)
        {
            int? bits = CryptoEncoding.PublicKeyBits(cert);
            if (bits.HasValue) return bits.Value >= minimum;
            return cert.PublicKey.Oid.Value == "1.2.840.10045.2.1" || VerifyKeySize(PublicKeyCache.Get(cert), minimum);
        }
        internal static bool VerifyKeySize(AsymmetricAlgorithm key, int minimum) => key != null && (!(key is RSA || key is DSA) || key.KeySize >= minimum);
    }
}
