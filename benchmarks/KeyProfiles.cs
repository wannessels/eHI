using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal static class KeyProfiles
{
    internal static async Task RunAsync()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Key profile", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] encoded = certificate.RawData, publicKey = certificate.PublicKey.EncodedKeyValue.RawData;
        var parameters = rsa.ExportParameters(false);
        byte[] hash = SHA256.HashData(encoded), signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        await Program.MeasureAsync("keys", "certificate-decode", encoded.Length, 2000, () => { using var copy = new X509Certificate2(encoded); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "certificate-copy", encoded.Length, 2000, () => { using var copy = new X509Certificate2(certificate); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "certificate-thumbprint", encoded.Length, 2000, () => { using var copy = new X509Certificate2(certificate); _ = copy.Thumbprint; return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "public-key-from-certificate", publicKey.Length, 2000, () => { using var key = certificate.GetRSAPublicKey(); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "private-key-from-certificate", publicKey.Length, 2000, () => { using var key = certificate.GetRSAPrivateKey(); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "public-key-import-rsa", publicKey.Length, 2000, () => { using var key = RSA.Create(); key.ImportRSAPublicKey(publicKey, out _); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "public-key-import-parameters", publicKey.Length, 2000, () => { using var key = RSA.Create(); key.ImportParameters(parameters); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "verify-hash", hash.Length, 2000, () =>
        {
            if (!rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new Exception("Verification failed");
            return Task.CompletedTask;
        });
        await Program.MeasureAsync("keys", "sign-hash", hash.Length, 200, () => { rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss); return Task.CompletedTask; });
        await Program.MeasureAsync("keys", "sign-hash-fresh-handle", hash.Length, 200, () => { using var key = certificate.GetRSAPrivateKey(); key.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss); return Task.CompletedTask; });
    }
}
