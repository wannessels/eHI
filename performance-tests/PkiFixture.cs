using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using BCert = Org.BouncyCastle.X509.X509Certificate;

internal class PkiFixture
{
    internal static AsymmetricCipherKeyPair NewKey() { using var rsa = RSA.Create(2048); return DotNetUtilities.GetRsaKeyPair(rsa); }
    internal static BCert MakeCert(string name, BigInteger serial, AsymmetricCipherKeyPair key, BCert issuer, AsymmetricCipherKeyPair issuerKey, string ocsp = null, string crl = null, bool timestamp = false, int? keyUsage = null)
    {
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(serial); gen.SetIssuerDN(issuer?.SubjectDN ?? new X509Name(name)); gen.SetSubjectDN(new X509Name(name));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1)); gen.SetNotAfter(DateTime.UtcNow.AddDays(2)); gen.SetPublicKey(key.Public);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(issuer == null));
        gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage ?? (issuer == null ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature)));
        if (timestamp) gen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
        if (ocsp != null) gen.AddExtension(X509Extensions.AuthorityInfoAccess, false, new AuthorityInformationAccess(AccessDescription.IdADOcsp, new GeneralName(GeneralName.UniformResourceIdentifier, ocsp)));
        if (crl != null) gen.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(new[] { new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crl))), null, null) }));
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", (issuerKey ?? key).Private));
    }
    internal static Egelke.EHealth.Client.Pki.CertificateRevocationList MakeCrl(BCert issuer, AsymmetricCipherKeyPair key, string distributionPoint = null, BigInteger revoked = null)
    {
        var gen = new X509V2CrlGenerator();
        gen.SetIssuerDN(issuer.SubjectDN); gen.SetThisUpdate(DateTime.UtcNow.AddMinutes(-1)); gen.SetNextUpdate(DateTime.UtcNow.AddHours(1));
        if (distributionPoint != null) gen.AddExtension(X509Extensions.IssuingDistributionPoint, true, new IssuingDistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, distributionPoint))), false, false, null, false, false));
        if (revoked != null) gen.AddCrlEntry(revoked, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        return Egelke.EHealth.Client.Pki.CertificateRevocationList.Parse(gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key.Private)).GetEncoded());
    }
    internal sealed class FixtureServer : IDisposable
    {
        readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        public byte[] Ocsp, Crl; public int OcspRequests, CrlRequests, DelayMilliseconds;
        public string Url { get; }
        public FixtureServer() { listener.Start(); Url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/"; _ = Run(); }
        async Task Run() {
            try { while (true) { var client = await listener.AcceptTcpClientAsync(); _ = Serve(client); } }
            catch (SocketException) {} catch (ObjectDisposedException) {}
        }
        async Task Serve(TcpClient client) {
            using (client) { using var stream = client.GetStream(); var head = new StringBuilder(); byte[] buf = new byte[1];
                while (!head.ToString().EndsWith("\r\n\r\n")) { if (await stream.ReadAsync(buf) == 0) return; head.Append((char)buf[0]); }
                int contentLength = 0;
                foreach (var line in head.ToString().Split("\r\n")) if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) contentLength = int.Parse(line.Substring(15).Trim());
                while (contentLength-- > 0) if (await stream.ReadAsync(buf) == 0) return;
                bool ocsp = head.ToString().StartsWith("POST /ocsp");
                if (ocsp) System.Threading.Interlocked.Increment(ref OcspRequests); else System.Threading.Interlocked.Increment(ref CrlRequests); if (DelayMilliseconds > 0) await Task.Delay(DelayMilliseconds);
                byte[] body = ocsp ? Ocsp : Crl; string status = body == null ? "500 Error" : "200 OK"; body ??= Array.Empty<byte>();
                string headers = "HTTP/1.1 " + status + "\r\nContent-Type: " + (ocsp ? "application/ocsp-response" : "application/pkix-crl") + "\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(headers)); await stream.WriteAsync(body);
            }
        }
        public void Dispose() => listener.Stop();
    }
}



