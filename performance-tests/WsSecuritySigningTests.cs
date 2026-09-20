using System;
using System.IdentityModel.Selectors;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Security;
using Xunit;

public class WsSecuritySigningTests
{
    private static X509Certificate2 Certificate(RSA rsa)
    {
#if LEGACY_RUNTIME
        var key = Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(rsa);
        return PkiFixture.WithKey(PkiFixture.MakeCert("CN=WS-Security", Org.BouncyCastle.Math.BigInteger.One, key, null, null, keyUsage: 128), key);
#else
        return new CertificateRequest("CN=WS-Security", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
#endif
    }

    private static CustomSecurityTokenProvider Provider(X509Certificate2 certificate)
    {
        var requirement = new SecurityTokenRequirement { TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate" };
        requirement.Properties["wss"] = WSS.Create(SecurityVersion.WSSecurity11);
        return new CustomSecurityTokenProvider(requirement, certificate, null);
    }

    [Fact]
    public async Task X509TokenIsBuiltOncePerCertificate()
    {
        using var rsa = RuntimeCompat.CreateRsa(2048);
        using var certificate = Certificate(rsa); using var other = new X509Certificate2(certificate);
        var token = await Provider(certificate).PrepareTokenAsync(TimeSpan.FromSeconds(5));
        Assert.Same(token, await Provider(certificate).PrepareTokenAsync(TimeSpan.FromSeconds(5)));
        Assert.NotSame(token, await Provider(other).PrepareTokenAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("BinarySecurityToken", token.TokenXml.LocalName);
    }

    [Fact]
    public async Task ConcurrentRequestsSignWithPooledHandlesAndVerify()
    {
        using var rsa = RuntimeCompat.CreateRsa(2048);
        using var certificate = Certificate(rsa);
        var token = await Provider(certificate).PrepareTokenAsync(TimeSpan.FromSeconds(5));
        var documents = await Task.WhenAll(Enumerable.Range(0, 16).Select(i => Task.Run(() =>
        {
            using var message = new CustomSecurityAppliedMessage(Message.CreateMessage(MessageVersion.Soap11, "urn:test", new byte[1024]))
            { MessageSecurityVersion = SecurityVersion.WSSecurity11, SignParts = SignParts.All, PreparedToken = token };
            using var buffer = new MemoryStream();
            using (var writer = XmlDictionaryWriter.CreateTextWriter(buffer, Encoding.UTF8, false)) message.WriteMessage(writer);
            var document = new XmlDocument { PreserveWhitespace = true };
            document.Load(new MemoryStream(buffer.ToArray()));
            return document;
        })));
        using var publicKey = certificate.GetRSAPublicKey();
        foreach (var document in documents)
        {
            var signature = (XmlElement)document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0];
            var signed = new CustomSignedXml(document); signed.LoadXml(signature);
            Assert.True(signed.CheckSignature(publicKey));
            Assert.Equal(3, signed.SignedInfo.References.Count);
        }
    }

    [Fact]
    public async Task PoolOpensAtMostTheLimitAndQueuesTheRest()
    {
        int opened = 0;
        using var pool = new SigningKeyPool(() => { Interlocked.Increment(ref opened); return RuntimeCompat.CreateRsa(2048); }, 2);
        var first = await pool.RentAsync(CancellationToken.None);
        var second = await pool.RentAsync(CancellationToken.None);
        Assert.NotSame(first.Key, second.Key);
        var third = pool.RentAsync(CancellationToken.None).AsTask();
        await Task.Delay(100);
        Assert.False(third.IsCompleted);
        first.Dispose();
        Assert.Same(first.Key, (await third).Key);
        Assert.Equal(2, opened);
    }
}
