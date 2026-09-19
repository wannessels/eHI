using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class WinSignatureFactory : ISignatureFactory
    {
        private readonly AlgorithmIdentifier algID;

        private readonly Oid hashOid;

        private readonly AsymmetricAlgorithm privateKey;

        public WinSignatureFactory(Oid algOid, Oid hashOid, AsymmetricAlgorithm privateKey)
        {
            DerObjectIdentifier doid = new DerObjectIdentifier(algOid.Value);
            algID = new AlgorithmIdentifier(doid); //we assume no params.

            this.hashOid = hashOid;
            this.privateKey = privateKey;
        }

        public object AlgorithmDetails => algID;

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return new WinStreamCalculator(hashOid, HashAlgorithm.Create(hashOid.FriendlyName), privateKey);
        }
    }
}
