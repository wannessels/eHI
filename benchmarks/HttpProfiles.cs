using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

internal static class HttpProfiles
{
    private sealed class ConnectionCounter { internal int Count; }
    private sealed class Destination { internal int Port; }
    internal static async Task<object> RunAsync()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=profile.invalid", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("profile.invalid");
        request.CertificateExtensions.Add(names.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        // Windows Schannel needs an imported key handle for the localhost TLS server.
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        await using var first = await Server.StartAsync("A", certificate);
        await using var second = await Server.StartAsync("B", certificate);
        var connectionCounts = new List<object>();
        foreach (string mode in new[] { "fresh-client", "shared-infinite", "shared-2min" })
        {
            var destination = new Destination { Port = first.Port };
            var counter = new ConnectionCounter();
            using var shared = CreateClient(destination, certificate.Thumbprint, counter,
                mode == "shared-2min" ? TimeSpan.FromMinutes(2) : Timeout.InfiniteTimeSpan);
            await Program.MeasureAsync("https-pooling", mode, 1024, 150, async () =>
            {
                if (mode == "fresh-client")
                {
                    using var client = CreateClient(destination, certificate.Thumbprint, counter, Timeout.InfiniteTimeSpan);
                    await GetAsync(client);
                }
                else await GetAsync(shared);
            });
            connectionCounts.Add(new { mode, connections = counter.Count });
        }
        foreach (int limit in new[] { 4, 32 })
        {
            var destination = new Destination { Port = first.Port };
            var counter = new ConnectionCounter();
            using var client = CreateClient(destination, certificate.Thumbprint, counter, TimeSpan.FromMinutes(2), limit);
            await Program.MeasureAsync("https-batch16-delay10ms", $"max-connections-{limit}", 16 * 1024, 30,
                () => Task.WhenAll(Enumerable.Range(0, 16).Select(_ => GetAsync(client, "?delay=10"))));
            connectionCounts.Add(new { mode = $"batch16-max-{limit}", connections = counter.Count });
        }
        var rotation = new List<object>();
        foreach (bool finite in new[] { false, true })
        {
            var destination = new Destination { Port = first.Port };
            var counter = new ConnectionCounter();
            using var client = CreateClient(destination, certificate.Thumbprint, counter, finite ? TimeSpan.FromMilliseconds(100) : Timeout.InfiniteTimeSpan);
            string before = await GetAsync(client);
            destination.Port = second.Port;
            await Task.Delay(250);
            string after = await GetAsync(client);
            if (before != "A" || after != (finite ? "B" : "A")) throw new Exception("Unexpected connection rotation");
            rotation.Add(new { lifetime = finite ? "100ms" : "infinite", before, after, connections = counter.Count });
        }
        return new { connectionCounts, simulatedResolverRotation = rotation,
            note = "A ConnectCallback simulates a resolver changing destination ports while the hostname stays fixed. This is a connection-lifetime test, not a measurement of AWS DNS." };
    }
    private static HttpClient CreateClient(Destination destination, string certificateThumbprint, ConnectionCounter counter, TimeSpan lifetime, int maximum = 32)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false, PooledConnectionLifetime = lifetime, MaxConnectionsPerServer = maximum,
            SslOptions = new SslClientAuthenticationOptions
            {
                // Only accept this generated localhost fixture certificate; never a production setting.
                RemoteCertificateValidationCallback = (_, cert, _, _) => cert?.GetCertHashString() == certificateThumbprint
            },
            ConnectCallback = async (_, token) =>
            {
                Interlocked.Increment(ref counter.Count);
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, destination.Port), token);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            }
        };
        return new HttpClient(handler) { BaseAddress = new Uri("https://profile.invalid/"), Timeout = TimeSpan.FromSeconds(10), DefaultRequestVersion = HttpVersion.Version11 };
    }
    private static async Task<string> GetAsync(HttpClient client, string path = "")
    {
        using var response = await client.GetAsync(path);
        response.EnsureSuccessStatusCode();
        if ((await response.Content.ReadAsByteArrayAsync()).Length != 1024) throw new Exception("Wrong HTTP body length");
        return response.Headers.GetValues("X-Benchmark-Server").Single();
    }
    private sealed class Server : IAsyncDisposable
    {
        private readonly WebApplication app;
        internal int Port { get; }
        private Server(WebApplication app) { this.app = app; Port = new Uri(app.Urls.Single()).Port; }
        internal static async Task<Server> StartAsync(string id, X509Certificate2 certificate)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen =>
            {
                listen.Protocols = HttpProtocols.Http1; listen.UseHttps(certificate);
            }));
            var app = builder.Build();
            byte[] response = new byte[1024];
            app.MapGet("/", async context =>
            {
                if (context.Request.Query.ContainsKey("delay")) await Task.Delay(10, context.RequestAborted);
                context.Response.Headers["X-Benchmark-Server"] = id;
                context.Response.ContentLength = response.Length;
                await context.Response.Body.WriteAsync(response, context.RequestAborted);
            });
            await app.StartAsync();
            return new Server(app);
        }
        public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); }
    }
}
