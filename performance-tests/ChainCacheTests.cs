using System;
using System.Linq;
using System.Diagnostics.Metrics;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Math;
using Xunit;

[Collection("Revocation")]
public class ChainCacheTests : IDisposable
{
    private readonly X509Certificate2Collection previous = X509CertificateHelper.CustomTrustStore;
    private readonly TimeSpan lifetime = ChainCache.Lifetime;
    public ChainCacheTests() { ChainCache.Clear(); }
    public void Dispose() { X509CertificateHelper.CustomTrustStore = previous; ChainCache.Lifetime = lifetime; ChainCache.Clear(); }

    private static void DisposeChain(Chain chain) { foreach (var element in chain.ChainElements) element.Certificate.Dispose(); }

    [Fact]
    public void InPlaceTrustRemovalAndDisabledCachingTakeEffectImmediately()
    {
        var key = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Mutable Trust Root", BigInteger.One, key, null, null);
        using var certificate = new X509Certificate2(root.GetEncoded());
        var trust = new X509Certificate2Collection(certificate);
        X509CertificateHelper.CustomTrustStore = trust;
        var initial = certificate.BuildChain(DateTime.UtcNow, null);
        Assert.Empty(initial.ChainStatus); DisposeChain(initial);
        var cached = certificate.BuildChain(DateTime.UtcNow, null);
        Assert.Equal(1, ChainCache.Hits); DisposeChain(cached);

        ChainCache.Lifetime = TimeSpan.Zero;
        DisposeChain(certificate.BuildChain(DateTime.UtcNow, null));
        Assert.Equal(0, ChainCache.Hits); Assert.Equal(0, ChainCache.Count);

        ChainCache.Lifetime = lifetime;
        DisposeChain(certificate.BuildChain(DateTime.UtcNow, null));
        trust.Clear();
        var removed = certificate.BuildChain(DateTime.UtcNow, null);
        Assert.Contains(removed.ChainStatus, s => s.Status == X509ChainStatusFlags.UntrustedRoot);
        DisposeChain(removed);
    }

    [Fact]
    public void BuildStartedBeforeTrustChangeCannotPopulateNewCacheGeneration()
    {
        var key = PkiFixture.NewKey(); var root = PkiFixture.MakeCert("CN=Changing Trust Root", BigInteger.One, key, null, null);
        using var certificate = new X509Certificate2(root.GetEncoded());
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(certificate);
        bool changed = false;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, subscriber) =>
        {
            if (instrument.Meter.Name == EHealthMetrics.MeterName && instrument.Name == "ehealth.chain.builds") subscriber.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, state) =>
        {
            if (changed) return;
            foreach (var tag in tags)
                if (tag.Key == "source" && (string)tag.Value == "platform")
                { changed = true; X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(); }
        });
        listener.Start();
        var oldOperation = certificate.BuildChain(DateTime.UtcNow, null);
        Assert.True(changed); Assert.Empty(oldOperation.ChainStatus); DisposeChain(oldOperation);
        Assert.Equal(0, ChainCache.Count);
        var next = certificate.BuildChain(DateTime.UtcNow, null);
        Assert.Contains(next.ChainStatus, s => s.Status == X509ChainStatusFlags.UntrustedRoot); DisposeChain(next);
    }

    [Fact]
    public void SuccessfulSystemTrustIsReevaluatedByThePlatform()
    {
        X509CertificateHelper.CustomTrustStore = null;
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var certificates = store.Certificates;
        try
        {
            // Store membership and date validity do not imply a usable trusted path:
            // hosted Windows runners also contain roots rejected by platform policy.
            // Select the fixture with an independent platform build, then verify that
            // the library repeats that successful decision without serving a cache hit.
            DateTime time = DateTime.UtcNow;
            var certificate = certificates.Cast<X509Certificate2>().FirstOrDefault(candidate =>
            {
                if (!CryptoEncoding.ValidAt(candidate, time) || !CryptoEncoding.NamesEqual(candidate.SubjectName.RawData, candidate.IssuerName.RawData)) return false;
                using var platform = new X509Chain();
                platform.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                platform.ChainPolicy.VerificationTime = time;
                platform.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                return platform.Build(candidate);
            });
            Assert.NotNull(certificate);
            for (int i = 0; i < 2; i++)
            {
                var chain = certificate.BuildChain(time, null);
                Assert.Empty(chain.ChainStatus); DisposeChain(chain);
            }
            Assert.Equal(0, ChainCache.Count); Assert.Equal(0, ChainCache.Hits); Assert.Equal(2, ChainCache.Misses);
        }
        finally { X509CertificateHelper.DisposeAll(certificates); }
    }

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
