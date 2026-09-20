using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public class ConcurrentSigningTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task EcdsaSignsIndependentConcurrentMessages(bool native)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var sender = new WebKey(key);
        var recipient = new SecretKey(new byte[] { 1 }, RandomNumberGenerator.GetBytes(16));
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, native).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 32).Select(i => Task.Run(async () =>
            {
                byte[] data = BitConverter.GetBytes(i);
                using var input = new MemoryStream(data); using var encrypted = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
                var result = await receiver.UnsealAsync(encrypted, sender, recipient);
                using (result.UnsealedData) using (var output = new MemoryStream())
                { result.UnsealedData.CopyTo(output); Assert.Equal(data, output.ToArray()); Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus); }
            })));
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
}
