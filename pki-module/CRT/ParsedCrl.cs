using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using BCAX = Org.BouncyCastle.Asn1.X509;
using BCX = Org.BouncyCastle.X509;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Parsed form of a CRL, with the signature verified once and the revoked serials indexed.
    /// </summary>
    internal sealed class ParsedCrl
    {
        private static readonly ConditionalWeakTable<BCAX.CertificateList, ParsedCrl> cache = new ConditionalWeakTable<BCAX.CertificateList, ParsedCrl>();

        public static ParsedCrl Get(BCAX.CertificateList list)
        {
            return cache.GetValue(list, l => new ParsedCrl(l));
        }

        private readonly object sync = new object();
        private AsymmetricKeyParameter verifiedWith;
        private Dictionary<BigInteger, BCX.X509CrlEntry> revoked;

        public BCX.X509Crl Crl { get; }

        private ParsedCrl(BCAX.CertificateList list)
        {
            Crl = new BCX.X509Crl(list);
        }

        public void Verify(AsymmetricKeyParameter issuerKey)
        {
            lock (sync)
            {
                if (issuerKey.Equals(verifiedWith)) return;
                Crl.Verify(issuerKey);
                verifiedWith = issuerKey;
            }
        }

        public BCX.X509CrlEntry GetRevokedCertificate(BigInteger serial)
        {
            lock (sync)
            {
                if (revoked == null)
                {
                    revoked = new Dictionary<BigInteger, BCX.X509CrlEntry>();
                    var entries = Crl.GetRevokedCertificates();
                    if (entries != null)
                    {
                        foreach (BCX.X509CrlEntry entry in entries)
                        {
                            revoked[entry.SerialNumber] = entry;
                        }
                    }
                }
                return revoked.TryGetValue(serial, out BCX.X509CrlEntry found) ? found : null;
            }
        }
    }
}
