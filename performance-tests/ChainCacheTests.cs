using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Math;
using Xunit;

public class ChainCacheTests : IDisposable
{
    private readonly X509Certificate2Collection previous = X509CertificateHelper.CustomTrustStore;
    public ChainCacheTests() { ChainCache.Clear(); }
    public void Dispose() { X509CertificateHelper.CustomTrustStore = previous; ChainCache.Clear(); }

    [Fact]
    public void ReusesValidPathsAndRebuildsOutsideValidityOrWithErrors()
    {
        var rootKey = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Cache Root", BigInteger.One, rootKey, null, null);
        var leafKey = PkiFixture.NewKey(); var leaf = PkiFixture.MakeCert("CN=Cache Leaf", BigInteger.Two, leafKey, root, rootKey);
        using var rootCert = new X509Certificate2(root.GetEncoded()); using var leafCert = new X509Certificate2(leaf.GetEncoded());
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert);
        var first = leafCert.BuildChain(DateTime.UtcNow, null);
        Assert.Empty(first.ChainStatus); Assert.Equal(2, first.ChainElements.Count); Assert.Equal(1, ChainCache.Count);
        var second = leafCert.BuildChain(DateTime.UtcNow, null);
        Assert.Equal(first.ChainElements.Select(e => e.Certificate.Thumbprint), second.ChainElements.Select(e => e.Certificate.Thumbprint));
        Assert.All(second.ChainElements, e => Assert.DoesNotContain(first.ChainElements, f => ReferenceEquals(f.Certificate, e.Certificate)));
        foreach (var element in first.ChainElements) element.Certificate.Dispose();
        Assert.Empty(second.ChainStatus); Assert.All(second.ChainElements, e => Assert.NotNull(e.Certificate.Subject));
        var expired = leafCert.BuildChain(DateTime.UtcNow.AddDays(-3), null);
        Assert.Contains(expired.ChainStatus, s => s.Status == X509ChainStatusFlags.NotTimeValid);
        Assert.Equal(1, ChainCache.Count);
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection();
        Assert.Equal(0, ChainCache.Count);
        var untrusted = leafCert.BuildChain(DateTime.UtcNow, null);
        Assert.NotEmpty(untrusted.ChainStatus); Assert.Equal(0, ChainCache.Count);
    }
}
