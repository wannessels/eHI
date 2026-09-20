using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Security;

// The client-side SOAP work per request that the pharmacy scenario leaves out: WCF serialization of a
// base64 body, and the WS-Security header with signed timestamp, body and X.509 token that EhBinding applies.
internal static class SoapProfiles
{
    private const string SecExtNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private const string UtilityNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private const string X509ProfileNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";
    private const string SecurityNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";

    internal static async Task RunAsync()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("SERIALNUMBER=12345678, CN=Benchmark pharmacy, C=BE", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        foreach (int size in new[] { 4 * 1024, 64 * 1024, 1024 * 1024 })
        {
            byte[] payload = RandomNumberGenerator.GetBytes(size);
            int iterations = size > 100 * 1024 ? 40 : 200;
            await Program.MeasureAsync("soap", "serialize-body", size, iterations, () =>
            {
                Write(Message.CreateMessage(MessageVersion.Soap11, "urn:bench", payload));
                return Task.CompletedTask;
            });
            await Program.MeasureAsync("soap", "sign-request", size, iterations, () =>
            {
                Write(new CustomSecurityAppliedMessage(Message.CreateMessage(MessageVersion.Soap11, "urn:bench", payload))
                {
                    MessageSecurityVersion = SecurityVersion.WSSecurity11, SignParts = SignParts.All, PreparedToken = Token(certificate)
                });
                return Task.CompletedTask;
            });
        }
    }
    private static void Write(Message message)
    {
        using (message)
        using (var writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false)) { message.WriteMessage(writer); writer.Flush(); }
    }
    private static GenericXmlSecurityToken Token(X509Certificate2 certificate)
    {
        string id = "urn:uuid:" + Guid.NewGuid();
        var document = new XmlDocument();
        var token = document.CreateElement("wsse", "BinarySecurityToken", SecExtNs);
        var tokenId = document.CreateAttribute("wsu", "Id", UtilityNs); tokenId.Value = id; token.Attributes.Append(tokenId);
        token.SetAttribute("ValueType", X509ProfileNs + "#X509v3"); token.SetAttribute("EncodingType", SecurityNs + "#Base64Binary");
        token.AppendChild(document.CreateTextNode(Convert.ToBase64String(certificate.RawData)));
        var reference = document.CreateElement("wsse", "SecurityTokenReference", SecExtNs);
        var pointer = document.CreateElement("wsse", "Reference", SecExtNs);
        pointer.SetAttribute("URI", "#" + id); pointer.SetAttribute("ValueType", X509ProfileNs + "#X509v3"); reference.AppendChild(pointer);
        return new GenericXmlSecurityToken(token, new X509SecurityToken(certificate), certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(), new GenericXmlSecurityKeyIdentifierClause(reference), null, null);
    }
}
