using System.IdentityModel.Selectors;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Security;

// The client-side SOAP work per request that the pharmacy scenario leaves out: WCF serialization of a
// base64 body, and the WS-Security header with signed timestamp, body and X.509 token that EhBinding applies.
internal static class SoapProfiles
{
    internal static async Task RunAsync()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("SERIALNUMBER=12345678, CN=Benchmark pharmacy, C=BE", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var requirement = new SecurityTokenRequirement { TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate" };
        requirement.Properties["wss"] = WSS.Create(SecurityVersion.WSSecurity11);
        foreach (int size in new[] { 4 * 1024, 64 * 1024, 1024 * 1024 })
        {
            byte[] payload = RandomNumberGenerator.GetBytes(size);
            int iterations = size > 100 * 1024 ? 40 : 200;
            await Program.MeasureAsync("soap", "serialize-body", size, iterations, () =>
            {
                Write(Message.CreateMessage(MessageVersion.Soap11, "urn:bench", payload));
                return Task.CompletedTask;
            });
            await Program.MeasureAsync("soap", "sign-request", size, iterations, async () =>
            {
                var token = await new CustomSecurityTokenProvider(requirement, certificate, null).PrepareTokenAsync(TimeSpan.FromSeconds(5));
                Write(new CustomSecurityAppliedMessage(Message.CreateMessage(MessageVersion.Soap11, "urn:bench", payload))
                {
                    MessageSecurityVersion = SecurityVersion.WSSecurity11, SignParts = SignParts.All, PreparedToken = token
                });
            });
        }
    }
    private static void Write(Message message)
    {
        using (message)
        using (var writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false)) { message.WriteMessage(writer); writer.Flush(); }
    }
}
