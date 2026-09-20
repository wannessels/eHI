using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Xunit;

[Collection("Revocation")]
public class SigningTimeValidityTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task CertificateExpiredAfterSigningStillValidatesAtSigningTime(bool native)
    {
        var rootKey = PkiFixture.NewKey(); var key = PkiFixture.NewKey();
        var expiry = DateTime.UtcNow.AddSeconds(3);
        var root = PkiFixture.MakeCert("CN=Short Root", BigInteger.One, rootKey, null, null);
        var leaf = PkiFixture.MakeCert("SERIALNUMBER=42, CN=Short Signer", BigInteger.Two, key, root, rootKey, notAfter: expiry);
        using var rootCert = new X509Certificate2(root.GetEncoded());
        using var rsa = RSA.Create(); rsa.ImportParameters(DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)key.Private));
        using var publicCert = new X509Certificate2(leaf.GetEncoded()); using var signer = publicCert.CopyWithPrivateKey(rsa);
        var previous = X509CertificateHelper.CustomTrustStore;
        X509CertificateHelper.CustomTrustStore = new X509Certificate2Collection(rootCert);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, native).Create(Level.B_Level, signer);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        var recipient = new SecretKey(new byte[] { 7 }, RandomNumberGenerator.GetBytes(16));
        try
        {
            using var input = new MemoryStream(new byte[] { 1, 2, 3 });
            using var sealedData = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
            while (DateTime.UtcNow <= expiry.AddSeconds(1)) await Task.Delay(250);
            Assert.True(DateTime.UtcNow > signer.NotAfter.ToUniversalTime());
            ChainCache.Clear();
            foreach (string path in new[] { "platform", "cache" })
            {
                sealedData.Position = 0;
                var result = await receiver.UnsealAsync(sealedData, recipient);
                using (result.UnsealedData)
                {
                    Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                    Assert.Equal(TrustStatus.Full, result.SecurityInformation.TrustStatus);
                }
                Assert.True(ChainCache.Count > 0, path);
            }
            Assert.True(ChainCache.Hits > 0);
        }
        finally
        {
            (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose();
            X509CertificateHelper.CustomTrustStore = previous; ChainCache.Clear();
        }
    }
}
