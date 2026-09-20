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
    // Run alone in a fresh process to compare process peak RSS without contamination
    // from earlier payload sizes or the other backend.
    internal static Task NativeMemoryAsync(int payloadMiB = 8) => RoundTripAsync(checked(payloadMiB * 1024 * 1024), 1024 * 1024, "isolated-memory", true);

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
            var managed = new Asn1SignatureFactory("SHA256WITHRSAANDMGF1", pair.Private);
            var factories = new (string Name, Func<byte[], byte[]> Sign)[] { ("bouncycastle-oracle", data => Sign(managed, data)), ("platform", data => key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) };
            foreach (int size in new[] { 64, 256 * 1024 })
            {
                byte[] data = RandomNumberGenerator.GetBytes(size);
                foreach (var mode in factories)
                {
                    if (!key.VerifyData(data, mode.Sign(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new Exception("Signature failed validation");
                    await Program.MeasureAsync("signing", $"rsa{bits}-{mode.Name}", size, 200, () =>
                    {
                        if (mode.Sign(data).Length != bits / 8) throw new Exception("Wrong signature length");
                        return Task.CompletedTask;
                    });
                }
            }
        }
        foreach (bool native in new[] { true, false })
        {
            foreach (int size in new[] { 32 * 1024, 1024 * 1024, 1024 * 1024 + 1, 8 * 1024 * 1024 })
                await RoundTripAsync(size, 1024 * 1024, "default-threshold", native);
            foreach (int size in new[] { 1024 * 1024, 1024 * 1024 + 1, 8 * 1024 * 1024 })
                await RoundTripAsync(size, 64 * 1024 * 1024, "memory-threshold", native);
        }
    }
    private static async Task RoundTripAsync(int size, long threshold, string scenario, bool native)
    {

        long previousThreshold = Settings.Default.InMemorySize;
        try
        {

            Settings.Default.InMemorySize = threshold;
            using var key = RSA.Create(2048);
            var sender = new WebKey(key);
            var recipient = new SecretKey(new byte[] { 1, 2, 3 }, RandomNumberGenerator.GetBytes(16));
            var sealer = new DataSealerFactory(NullLoggerFactory.Instance, native).Create(Level.B_Level, sender);
            var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, native).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection(), Array.Empty<WebKey>());
            var bytes = RandomNumberGenerator.GetBytes(size);
            try
            {
                await Program.MeasureAsync("cms-roundtrip", $"{(native ? "platform" : "bouncycastle")}-{scenario}", size, size > 1024 * 1024 ? 12 : 40, async () =>
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
            finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
        }
        finally { Settings.Default.InMemorySize = previousThreshold; }
    }
}
