using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

internal static class CryptoProfiles
{
    internal static ISignatureFactory Native(RSA key)
    {
        var type = typeof(WebKey).Assembly.GetType("Egelke.EHealth.Etee.Crypto.Utils.NativeRsaPssSignatureFactory")!;
        return (ISignatureFactory)Activator.CreateInstance(type, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { key }, null)!;
    }
    internal static byte[] Sign(ISignatureFactory factory, byte[] data)
    {
        var calculator = factory.CreateCalculator();
        using (var stream = calculator.Stream) stream.Write(data, 0, data.Length);
        return calculator.GetResult().Collect();
    }
    internal static async Task RunAsync()
    {
        foreach (int bits in new[] { 2048, 3072 })
        {
            using var key = RSA.Create(bits);
            var pair = DotNetUtilities.GetRsaKeyPair(key);
            var factories = new[] { (Name: "bouncycastle", Factory: (ISignatureFactory)new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", pair.Private)), (Name: "native", Factory: Native(key)) };
            foreach (int size in new[] { 64, 256 * 1024 })
            {
                byte[] data = RandomNumberGenerator.GetBytes(size);
                foreach (var mode in factories)
                {
                    if (!key.VerifyData(data, Sign(mode.Factory, data), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new Exception("Signature failed validation");
                    await Program.MeasureAsync("signing", $"rsa{bits}-{mode.Name}", size, 200, () =>
                    {
                        if (Sign(mode.Factory, data).Length != bits / 8) throw new Exception("Wrong signature length");
                        return Task.CompletedTask;
                    });
                }
            }
        }
        foreach (bool native in new[] { false, true })
            foreach (int size in new[] { 32 * 1024, 1024 * 1024, 1024 * 1024 + 1, 8 * 1024 * 1024 })
                await RoundTripAsync(native, size, 1024 * 1024, "default-threshold");
        foreach (int size in new[] { 1024 * 1024, 1024 * 1024 + 1, 8 * 1024 * 1024 })
            await RoundTripAsync(true, size, 64 * 1024 * 1024, "memory-threshold");
    }
    private static async Task RoundTripAsync(bool native, int size, long threshold, string scenario)
    {
        bool previous = Settings.Default.UseNativeRsaPss;
        long previousThreshold = Settings.Default.InMemorySize;
        try
        {
            Settings.Default.UseNativeRsaPss = native;
            Settings.Default.InMemorySize = threshold;
            using var key = RSA.Create(2048);
            var sender = new WebKey(key);
            var recipient = new SecretKey(new byte[] { 1, 2, 3 }, RandomNumberGenerator.GetBytes(16));
            var sealer = new DataSealerFactory(NullLoggerFactory.Instance).Create(Level.B_Level, sender);
            var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
            var bytes = RandomNumberGenerator.GetBytes(size);
            try
            {
                await Program.MeasureAsync("cms-roundtrip", $"{(native ? "native" : "bouncycastle")}-{scenario}", size, size > 1024 * 1024 ? 12 : 40, async () =>
                {
                    using var input = new MemoryStream(bytes, false);
                    using var output = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
                    var result = await receiver.UnsealAsync(output, sender, recipient);
                    using (result.UnsealedData)
                    {
                        if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid || result.UnsealedData.Length != size) throw new Exception("CMS roundtrip failed");
                        result.UnsealedData.Position = size - 1;
                        if (result.UnsealedData.ReadByte() != bytes[size - 1]) throw new Exception("CMS content mismatch");
                    }
                });
            }
            finally { (sealer as IDisposable)?.Dispose(); }
        }
        finally { Settings.Default.UseNativeRsaPss = previous; Settings.Default.InMemorySize = previousThreshold; }
    }
}
