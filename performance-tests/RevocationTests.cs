using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Xunit;

[CollectionDefinition("Revocation", DisableParallelization = true)]
public class RevocationCollection { }

[Collection("Revocation")]
public class RevocationTests : IDisposable
{
    private readonly int entryLimit = RevocationCache.EntryLimit;
    private readonly long byteLimit = RevocationCache.SizeLimitBytes;
    public RevocationTests() { RevocationCache.Clear(); }
    public void Dispose() { RevocationCache.Clear(); RevocationCache.EntryLimit = entryLimit; RevocationCache.SizeLimitBytes = byteLimit; }

    [Fact]
    public async Task ConcurrentDownloadsShareTheRequestAndFailedRequestsCanRetry()
    {
        using (var server = new PkiFixture.FixtureServer())
        {
            var key = PkiFixture.NewKey();
            var root = PkiFixture.MakeCert("CN=Root", BigInteger.One, key, null, null);
            using (var cert = new X509Certificate2(PkiFixture.MakeCert("CN=Leaf", BigInteger.Two, key, root, key, crl: server.Url + "crl").GetEncoded()))
            {
                server.DelayMilliseconds = 150;
                var failed = Enumerable.Range(0, 16).Select(_ => cert.GetCertificateListAsync()).ToArray();
                foreach (var task in failed) await Assert.ThrowsAsync<RevocationUnknownException>(() => task);
                Assert.Equal(1, server.CrlRequests);
                server.Crl = PkiFixture.MakeCrl(root, key).GetEncoded();
                var successes = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => cert.GetCertificateListAsync()));
                Assert.Equal(2, server.CrlRequests);
                Assert.All(successes, response => Assert.Same(successes[0], response));
            }
        }
    }

    [Fact]
    public async Task InvalidOcspFallsBackAndIsNotCached()
    {
        using (var server = new PkiFixture.FixtureServer())
        {
            var key = PkiFixture.NewKey();
            var root = PkiFixture.MakeCert("CN=Root", BigInteger.One, key, null, null);
            var leaf = PkiFixture.MakeCert("CN=Leaf", BigInteger.Two, key, root, key, server.Url + "ocsp", server.Url + "crl");
            using (var cert = new X509Certificate2(leaf.GetEncoded()))
            using (var issuer = new X509Certificate2(root.GetEncoded()))
            {
                var gen = new BasicOcspRespGenerator(key.Public);
                gen.AddResponse(new CertificateID(new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), root, leaf.SerialNumber), CertificateStatus.Good, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), null);
                var bad = gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", PkiFixture.NewKey().Private), new[] { root }, DateTime.UtcNow);
                server.Ocsp = new OcspResponse(new OcspResponseStatus(0), new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic, new DerOctetString(bad.GetEncoded()))).GetEncoded();
                server.Crl = PkiFixture.MakeCrl(root, key, revoked: leaf.SerialNumber).GetEncoded();
                var chain = await cert.BuildChainAsync(DateTime.UtcNow, new X509Certificate2Collection(issuer), new List<CertificateList>(), new List<BasicOcspResponse>());
                Assert.Contains(chain.ChainStatus, s => s.Status == X509ChainStatusFlags.Revoked);
                Assert.Equal(1, server.CrlRequests);
                object[] args = { cert, issuer, null };
                Assert.False((bool)typeof(RevocationCache).GetMethod("TryGetOcsp", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, args));
            }
        }
    }

    [Fact]
    public void CrlPartitionsAreNotInterchangeableAndCacheIsBounded()
    {
        var key = PkiFixture.NewKey();
        var root = PkiFixture.MakeCert("CN=Root", BigInteger.One, key, null, null);
        using (var issuer = new X509Certificate2(root.GetEncoded()))
        using (var a = new X509Certificate2(PkiFixture.MakeCert("CN=A", BigInteger.Two, key, root, key, crl: "http://example.invalid/a").GetEncoded()))
        using (var b = new X509Certificate2(PkiFixture.MakeCert("CN=B", BigInteger.Three, key, root, key, crl: "http://example.invalid/b").GetEncoded()))
        {
            var crlA = PkiFixture.MakeCrl(root, key, "http://example.invalid/a");
            Assert.Null(b.Verify(issuer, DateTime.UtcNow, new List<CertificateList> { crlA }));
            var put = typeof(RevocationCache).GetMethod("PutCrl", BindingFlags.NonPublic | BindingFlags.Static);
            put.Invoke(null, new object[] { a, issuer, crlA });
            object[] args = { b, issuer, null };
            Assert.False((bool)typeof(RevocationCache).GetMethod("TryGetCrl", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, args));
            RevocationCache.EntryLimit = 1;
            put.Invoke(null, new object[] { b, issuer, PkiFixture.MakeCrl(root, key, "http://example.invalid/b") });
            Assert.Equal(1, RevocationCache.Count);
            RevocationCache.SizeLimitBytes = 1;
            Assert.Equal(0, RevocationCache.Count);
            Assert.Equal(0, RevocationCache.EstimatedSizeBytes);
        }
    }
}
