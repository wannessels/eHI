using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Status;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;
using Xunit;

[Collection("Revocation")]
public class NativeEtkTests
{
    [Fact]
    public async Task DerivedEhealthEncryptionCertificateValidatesThroughItsAuthenticationIssuer()
    {
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Root", BigInteger.One, rootKey, null, null);
        var authKey = PkiFixture.NewKey(); var auth = PkiFixture.MakeCert("CN=Proxy Subject", BigInteger.Two, authKey, root, rootKey, keyUsage: 192);
        var encryptionKey = PkiFixture.NewKey(); var encryption = PkiFixture.MakeCert("CN=Proxy Subject", BigInteger.Three, encryptionKey, auth, authKey, keyUsage: 48);
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory("SHA256WITHRSA", authKey.Private), auth));
        generator.AddCertificates(CollectionUtilities.CreateStore(new[] { auth, root }));
        byte[] encoded = generator.Generate(new CmsProcessableByteArray(encryption.GetEncoded()), true).GetEncoded();
        using var rootCert = new X509Certificate2(root.GetEncoded());
        var previous = X509CertificateHelper.CustomTrustStore; X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert);
        try
        {
            var token = new EncryptionToken(encoded);
            Assert.Equal(encryption.GetEncoded(), token.ToCertificate().RawData);
            Assert.Same(token.ToCertificate(), token.ToCertificate());
            var validation = await token.VerifyAsync(false);
            Assert.Equal(ValidationStatus.Valid, validation.ValidationStatus);
            Assert.Equal(TrustStatus.Full, validation.TrustStatus);
            Assert.Equal(auth.GetEncoded(), validation.IssuerInfo.Certificate.RawData);
        }
        finally { X509CertificateHelper.CustomTrustStore = previous; }
    }
}
