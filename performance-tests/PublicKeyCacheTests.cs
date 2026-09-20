using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Xunit;

public class PublicKeyCacheTests
{
    [Fact]
    public void SharesKeysPerCertificateAndReadsKeySizesFromEncodings()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1); var notAfter = DateTimeOffset.UtcNow.AddDays(1);
        using var rsa = RSA.Create(2048); using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsaCertificate = new CertificateRequest("CN=RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(notBefore, notAfter);
        using var ecCertificate = new CertificateRequest("CN=EC", ecdsa, HashAlgorithmName.SHA256).CreateSelfSigned(notBefore, notAfter);
        using var copy = new X509Certificate2(rsaCertificate);
        var key = PublicKeyCache.Get(rsaCertificate);
        Assert.Same(key, PublicKeyCache.Get(copy));
        Assert.IsAssignableFrom<RSA>(key); Assert.IsAssignableFrom<ECDsa>(PublicKeyCache.Get(ecCertificate));
        Assert.Equal(2048, CryptoEncoding.PublicKeyBits(rsaCertificate)); Assert.Null(CryptoEncoding.PublicKeyBits(ecCertificate));
        byte[] hash = SHA256.HashData(new byte[] { 1 });
        byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.True(((RSA)key).VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }
}
