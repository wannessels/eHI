using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class WinStreamCalculator : IStreamCalculator<IBlockResult>
    {
        private readonly Oid hashOid;

        private readonly HashAlgorithm hashAlgorithm;

        private readonly AsymmetricAlgorithm privateKey;
        private readonly RSASignaturePadding padding;

        public WinStreamCalculator(Oid hashOid, HashAlgorithm hashAlgorithm, AsymmetricAlgorithm privateKey, RSASignaturePadding padding = null)
        {
            this.hashOid = hashOid;
            this.hashAlgorithm = hashAlgorithm;
            this.privateKey = privateKey;
            this.padding = padding ?? RSASignaturePadding.Pkcs1;
        }

        public Stream Stream => new HashAlgorithmProxy(hashAlgorithm);

        public IBlockResult GetResult()
        {
            return new WinSignatureResult(hashOid, hashAlgorithm, privateKey, padding);
        }
    }
}
