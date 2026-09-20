using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using Egelke.EHealth.Client.Pki;
using Xunit;

[Collection("Revocation")]
public class PortablePkiTests
{
#if LEGACY_RUNTIME && NET8_0_OR_GREATER
    [Fact]
    public void PackageConsumerLoadsTheNetStandardLibraries()
    {
        foreach (var assembly in new[] { typeof(EHealthP12).Assembly, typeof(Egelke.EHealth.Client.EhBinding).Assembly, typeof(Egelke.EHealth.Etee.Crypto.EncryptionToken).Assembly })
        {
            var target = (System.Runtime.Versioning.TargetFrameworkAttribute)Attribute.GetCustomAttribute(assembly, typeof(System.Runtime.Versioning.TargetFrameworkAttribute));
            Assert.Equal(".NETStandard,Version=v2.0", target.FrameworkName);
        }
    }
#endif
    [Fact]
    public void Pkcs12AliasesPrivateKeysAndPasswordValidation()
    {
        byte[] data = File.ReadAllBytes("fixtures/dummy.p12");
        using var store = new EHealthP12(data, "test001");
        Assert.Equal(5, store.Count);
        Assert.True(store["authenication"].HasPrivateKey);
        Assert.Same(store["authenication"], store["authenication"]);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => new EHealthP12(data, "incorrect"));
    }

    [Fact]
    public void HistoricalTimestampSignatureAndCertificateBinding()
    {
        var token = File.ReadAllBytes("fixtures/fedictTs.ts").ToTimeStampToken();
        var certificates = token.AsSignedCms().Certificates;
        try
        {
            Assert.True(token.VerifySignatureForHash(token.TokenInfo.GetMessageHash().Span, token.TokenInfo.HashAlgorithmId, out _, certificates));
            byte[] wrong = token.TokenInfo.GetMessageHash().ToArray(); wrong[0] ^= 1;
            Assert.False(token.VerifySignatureForHash(wrong, token.TokenInfo.HashAlgorithmId, out _, certificates));
        }
        finally { X509CertificateHelper.DisposeAll(certificates); }
    }

    [Fact]
    public void ModifiedTimestampSignatureIsRejected()
    {
        var content = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(File.ReadAllBytes("fixtures/fedictTs.ts"));
        var signed = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(content.Content);
        var signer = Org.BouncyCastle.Asn1.Cms.SignerInfo.GetInstance(signed.SignerInfos[0]);
        byte[] signature = signer.Signature.GetOctets(); signature[0] ^= 1;
        var changedSigner = new Org.BouncyCastle.Asn1.Cms.SignerInfo(signer.SignerID, signer.DigestAlgorithm, signer.SignedAttrs,
            signer.SignatureAlgorithm, new Org.BouncyCastle.Asn1.DerOctetString(signature), signer.UnsignedAttrs);
        byte[] encoded = new Org.BouncyCastle.Asn1.Cms.ContentInfo(content.ContentType,
            new Org.BouncyCastle.Asn1.Cms.SignedData(signed.DigestAlgorithms, signed.EncapContentInfo, signed.Certificates, signed.CRLs,
                new Org.BouncyCastle.Asn1.DerSet(changedSigner))).GetEncoded();
        Rfc3161TimestampToken token;
        try { token = encoded.ToTimeStampToken(); }
        catch (System.Security.Cryptography.CryptographicException) { return; } // Some platform versions reject the signature during decode.
        var certificates = token.AsSignedCms().Certificates;
        try { Assert.False(token.VerifySignatureForHash(token.TokenInfo.GetMessageHash().Span, token.TokenInfo.HashAlgorithmId, out _, certificates)); }
        finally { X509CertificateHelper.DisposeAll(certificates); }
    }
}
