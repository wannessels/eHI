#if NETSTANDARD2_0
using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Compatibility
{
    // WCF 4.x does not publicly expose X509SecurityToken on .NET Standard.
    // Our custom WS-Security channel signs through Certificate's provider itself.
    internal sealed class CertificateProofToken : SecurityToken
    {
        internal CertificateProofToken(X509Certificate2 certificate) { Certificate = certificate; }
        internal X509Certificate2 Certificate { get; }
        public override string Id { get; } = "urn:uuid:" + Guid.NewGuid();
        public override DateTime ValidFrom => Certificate.NotBefore.ToUniversalTime();
        public override DateTime ValidTo => Certificate.NotAfter.ToUniversalTime();
        public override ReadOnlyCollection<SecurityKey> SecurityKeys { get; } = new ReadOnlyCollection<SecurityKey>(Array.Empty<SecurityKey>());
    }
}
#endif
