using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Xunit;

[CollectionDefinition("Crypto settings", DisableParallelization = true)]
public class CryptoSettingsCollection { }

[Collection("Crypto settings")]
public class NativeRsaPssTests
{
    internal static ISignatureFactory NativeFactory(RSA key)
    {
        var type = typeof(WebKey).Assembly.GetType("Egelke.EHealth.Etee.Crypto.Utils.NativeRsaPssSignatureFactory");
        return (ISignatureFactory)Activator.CreateInstance(type, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { key }, null);
    }
    private static byte[] Sign(ISignatureFactory factory, byte[] data)
    {
        var calculator = factory.CreateCalculator();
        using (var stream = calculator.Stream) stream.Write(data, 0, data.Length);
        return calculator.GetResult().Collect();
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public async Task PlatformAndBouncyCastlePssHaveIdenticalParametersAndCrossVerify(int bits)
    {
        using (var key = RSA.Create(bits))
        {
            var pair = DotNetUtilities.GetRsaKeyPair(key);
            var managed = new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", pair.Private);
            var native = NativeFactory(key);
            Assert.Equal(((AlgorithmIdentifier)managed.AlgorithmDetails).GetEncoded(), ((AlgorithmIdentifier)native.AlgorithmDetails).GetEncoded());
            await Task.WhenAll(Enumerable.Range(0, 16).Select(i => Task.Run(() =>
            {
                var data = BitConverter.GetBytes(i);
                var signature = Sign(native, data);
                var verifier = SignerUtilities.GetSigner("SHA256WITHRSAANDMGF1");
                verifier.Init(false, pair.Public);
                verifier.BlockUpdate(data, 0, data.Length);
                Assert.True(verifier.VerifySignature(signature));
                var managedSignature = Sign(new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", pair.Private), data);
                using (var publicKey = RSA.Create())
                {
                    publicKey.ImportParameters(key.ExportParameters(false));
                    Assert.True(publicKey.VerifyData(data, managedSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                }
            })));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CertificateSigningProducesVerifiableDetachedCmsInBothModes(bool native)
    {
        bool previous = Settings.Default.UseNativeRsaPss;
        try
        {
            Settings.Default.UseNativeRsaPss = native;
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=Local signing fixture", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
                using (var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1)))
                using (var input = new MemoryStream(new byte[2048]))
                using (var output = new MemoryStream())
                {
                    var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, cert);
                    try
                    {
                        var sign = sealer.GetType().GetMethod("SignDetached", BindingFlags.NonPublic | BindingFlags.Instance, null,
                            new[] { typeof(Stream), typeof(Stream), typeof(X509Certificate2) }, null);
                        sign.Invoke(sealer, new object[] { output, input, cert });
                        var cms = new CmsSignedData(new CmsProcessableByteArray(input.ToArray()), output.ToArray());
                        var signer = cms.GetSignerInfos().GetSigners().Single();
                        Assert.Equal("1.2.840.113549.1.1.10", signer.SignatureAlgorithm.Algorithm.Id);
                        Assert.True(signer.Verify(DotNetUtilities.GetRsaPublicKey(rsa)));
                    }
                    finally { (sealer as IDisposable)?.Dispose(); }
                    // Disposing cached native handles must not dispose the caller's certificate/key.
                    using (var owned = cert.GetRSAPrivateKey())
                        Assert.NotEmpty(owned.SignData(new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                }
            }
        }
        finally { Settings.Default.UseNativeRsaPss = previous; }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BothFlagModesRoundTripCmsWithoutChangingTheWireAlgorithm(bool native)
    {
        bool previous = Settings.Default.UseNativeRsaPss;
        try
        {
            Settings.Default.UseNativeRsaPss = native;
            using (var senderRsa = RSA.Create(2048))
            using (var clear = new MemoryStream(new byte[32 * 1024]))
            {
                var sender = new WebKey(senderRsa);
                var recipient = new SecretKey(new byte[] { 1, 2, 3, 4 }, RandomNumberGenerator.GetBytes(16));
                var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
                try
                {
                    using (var sealedData = await sealer.SealAsync(clear, recipient, Array.Empty<EncryptionToken>()))
                    {
                        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null,
                            new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
                        var result = await receiver.UnsealAsync(sealedData, sender, recipient);
                        using (result.UnsealedData)
                        using (var output = new MemoryStream())
                        {
                            result.UnsealedData.CopyTo(output);
                            Assert.Equal(clear.ToArray(), output.ToArray());
                            Assert.Equal(Egelke.EHealth.Etee.Crypto.Status.ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                        }
                    }
                }
                finally { (sealer as IDisposable)?.Dispose(); }
            }
        }
        finally { Settings.Default.UseNativeRsaPss = previous; }
    }
}
