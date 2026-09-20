using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Xunit;

public class CertificateCacheTests
{
    [Fact]
    public void DecodesOnceAndHandsOutIndependentCopies()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Cache", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] encoded = certificate.RawData;
        var first = CertificateCache.Load(encoded); var second = CertificateCache.Load(encoded);
        Assert.NotSame(first, second); Assert.Equal(certificate.Thumbprint, first.Thumbprint); Assert.Equal(certificate.Thumbprint, second.Thumbprint);
        Assert.True(CertificateCache.Count >= 1);
        first.Dispose();
        Assert.Equal("CN=Cache", second.Subject);
        second.Dispose();
        using var third = CertificateCache.Load(encoded);
        Assert.Equal("CN=Cache", third.Subject);
    }
}
