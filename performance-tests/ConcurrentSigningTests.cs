using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Org.BouncyCastle.Crypto;
using Xunit;

public class ConcurrentSigningTests
{
    [Fact]
    public async Task CachedNativeFactorySignsIndependentConcurrentMessages()
    {
        using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var factoryType = typeof(WebKey).Assembly.GetType("Egelke.EHealth.Etee.Crypto.Utils.WinSignatureFactory");
            var factory = (ISignatureFactory)Activator.CreateInstance(factoryType,
                new Oid("1.2.840.10045.4.3.2"), new Oid("2.16.840.1.101.3.4.2.1", "SHA256"), key);
            var publicKey = key.ExportSubjectPublicKeyInfo();
            await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(() =>
            {
                byte[] data = BitConverter.GetBytes(i);
                var calculator = factory.CreateCalculator();
                using (var stream = calculator.Stream) stream.Write(data, 0, data.Length);
                var result = calculator.GetResult();
                byte[] signature = result.Collect();
                Assert.Equal(signature, result.Collect());
                using (var verifier = ECDsa.Create())
                {
                    verifier.ImportSubjectPublicKeyInfo(publicKey, out _);
                    Assert.True(verifier.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
                }
            })));
        }
    }
}
