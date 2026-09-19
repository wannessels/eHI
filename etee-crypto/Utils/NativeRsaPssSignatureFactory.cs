using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // CMS encoding remains in BouncyCastle; hashing/signing use the platform implementation.
    internal sealed class NativeRsaPssSignatureFactory : ISignatureFactory
    {
        private static readonly AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
        private static readonly AlgorithmIdentifier algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsassaPss,
            new RsassaPssParameters(sha256, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, sha256), new DerInteger(32), new DerInteger(1)));
        private readonly RSA key;

        internal NativeRsaPssSignatureFactory(RSA key) { this.key = key ?? throw new ArgumentNullException(nameof(key)); }
        public object AlgorithmDetails => algorithm;
        public IStreamCalculator<IBlockResult> CreateCalculator()
            => new WinStreamCalculator(new Oid(NistObjectIdentifiers.IdSha256.Id, "SHA256"), SHA256.Create(), key, RSASignaturePadding.Pss);
    }
}
