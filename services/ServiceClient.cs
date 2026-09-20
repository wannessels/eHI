using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using TrustStatus = Egelke.EHealth.Etee.Crypto.Status.TrustStatus;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Egelke.EHealth.Client.Services
{
    public class ServiceClient<Port> : ClientBase<Port> where Port : class
    {
        protected readonly ILogger<ServiceClient<Port>> _logger;

        private OperationPolicy operationPolicy;
        /// <summary>Admission and deadline policy for complete service calls; follows the shared default unless overridden.</summary>
        /// <remarks>Assign null to return to the shared default. Configure policies before starting requests.</remarks>
        public OperationPolicy OperationPolicy
        {
            get => Volatile.Read(ref operationPolicy) ?? Egelke.EHealth.Client.Pki.OperationPolicy.Default;
            set => Volatile.Write(ref operationPolicy, value);
        }

        protected Task<T> RunOperationAsync<T>(Func<Task<T>> operation, CancellationToken cancellationToken)
            => OperationPolicy.RunAsync(_ => operation(), cancellationToken);

        protected async Task<T> SendAsync<T>(Func<Task<T>> send)
        {
            var cancellationToken = OperationScope.Cancellation;
            cancellationToken.ThrowIfCancellationRequested();
            using (cancellationToken.Register(Abort))
            {
                try { return await send().ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException(cancellationToken); }
            }
        }

        private readonly ResourceCache<Tuple<Level, X509Certificate2, bool>, IDataSealer> sealers =
            new ResourceCache<Tuple<Level, X509Certificate2, bool>, IDataSealer>((a, b) => a.Item1 == b.Item1 && ReferenceEquals(a.Item2, b.Item2) && a.Item3 == b.Item3);
        private readonly ResourceCache<Tuple<EHealthP12[], bool>, IDataUnsealer> unsealers =
            new ResourceCache<Tuple<EHealthP12[], bool>, IDataUnsealer>((a, b) => a.Item2 == b.Item2 && a.Item1.Length == b.Item1.Length && a.Item1.Zip(b.Item1, ReferenceEquals).All(equal => equal));

        public static ServiceClient<Port> Create(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
        {
            return new ServiceClient<Port>(store, binding, remoteAddress, logger);
        }

        public PartyInfo Sender { get; set; } = new PartyInfo();

        public PartyInfo Service { get; set; } = new PartyInfo();

        public EHealthP12 Store { get; set; }

        public List<EHealthP12> ExpiredStores { get; set; } = new List<EHealthP12>();

        protected ServiceClient(EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : this(null, new EhBinding(), remoteAddress, logger)
        { }

        protected ServiceClient(EHealthP12 store, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : this(store, new EhBinding(), remoteAddress, logger)
        { }

        protected ServiceClient(Binding binding, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : this(null, binding, remoteAddress, logger)
        { }


        protected ServiceClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : base(Enrich(binding, store), remoteAddress)
        {
            _logger = logger;
            Store = store;
            ((ICommunicationObject)this).Closed += DisposeCryptoContexts;
            ((ICommunicationObject)this).Faulted += DisposeCryptoContexts;

            if (store != null)
            {
                var idCert = Store["authentication"];
                Sender = PartyInfo.FromCertificate(idCert);
                ClientCredentials.ClientCertificate.Certificate = idCert;
            }
        }

        private void DisposeCryptoContexts(object sender, EventArgs args)
        {
            sealers.Dispose();
            unsealers.Dispose();
        }

        private static Binding Enrich(Binding binding, EHealthP12 store)
        {
            if (binding is EhBinding ehBinding && ehBinding.Security.Mode == EhSecurityMode.SamlFromWsTrust && store != null)
            {
                var id = PartyInfo.FromCertificate(store["authentication"]);
                if (id.HasId())
                {
                    foreach (var claim in id.ToAuthClaimSet())
                    {
                        ehBinding.Security.AuthClaims.Add(claim);
                    }
                }
            }
            return binding;
        }

        public void InitEncryptionTokens(EndpointAddress etkDepotAddress)
        {
            InitEncryptionTokens(new EtkDepotClient(etkDepotAddress));
        }

        public void InitEncryptionTokens(EtkDepotClient etkDepot)
        {
            if (etkDepot == null) throw new ArgumentNullException(nameof(etkDepot));

            if (Sender.Etk == null && Sender.HasId()) Sender.Etk = etkDepot.GetEtk(Sender.ToIdentifierType()).FirstOrDefault();
            if (Service.Etk == null && Service.HasId()) Service.Etk = etkDepot.GetEtk(Service.ToIdentifierType()).FirstOrDefault();
        }

        protected XmlElement ToXmlElement(byte[] bytes)
        {
            return ToXmlElement(new MemoryStream(bytes));
        }
        protected XmlElement ToXmlElement(Stream stream)
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(stream);

            return doc.DocumentElement;
        }

        protected XmlElement ToXmlElement(XDocument doc)
        {
            var xmlDoc = new XmlDocument();
            using (var reader = doc.CreateReader())
            {
                xmlDoc.Load(reader);
            }
            return xmlDoc.DocumentElement;
        }

        private static readonly XmlWriterSettings SerializeSettings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false), // Disable BOM
            Indent = true,                      // Optional: pretty print
            OmitXmlDeclaration = false,         // Include XML declaration
            IndentChars = "  ",
            NewLineHandling = NewLineHandling.Replace
        };

        protected MemoryStream ToMemoryStream(XmlElement el)
        {
            return ToMemoryStream(writer => el.WriteTo(writer));
        }

        protected MemoryStream ToMemoryStream(XDocument doc)
        {
            return ToMemoryStream(writer => doc.Save(writer));
        }

        private static MemoryStream ToMemoryStream(Action<XmlWriter> write)
        {
            var stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream, SerializeSettings))
            {
                write(writer);
            }
            stream.Position = 0;

            return stream;
        }

        protected byte[] ToByteArray(XmlElement el)
        {
            using (var stream = ToMemoryStream(el)) return stream.ToArray();
        }

        protected byte[] EncryptForService<ClearType>(ClearType clearText, Level level = Level.B_Level) where ClearType : class
        {
            return Encrypt(clearText, level, Service.Etk);
        }

        protected Task<byte[]> EncryptForServiceAsync<ClearType>(ClearType clearText, Level level = Level.B_Level) where ClearType : class
        {
            return EncryptAsync(clearText, level, Service.Etk);
        }

        protected byte[] Encrypt<ClearType>(ClearType clearText, Level level, params EncryptionToken[] recepients) where ClearType : class
        {
            return EncryptAsync(clearText, level, recepients).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        protected async Task<byte[]> EncryptAsync<ClearType>(ClearType clearText, Level level, params EncryptionToken[] recepients) where ClearType : class
        {
            Stream clearStream;
            switch (clearText)
            {
                case Stream stream:
                    clearStream = stream;
                    break;
                case byte[] bytes:
                    clearStream = new MemoryStream(bytes);
                    break;
                case XmlElement xmlElement:
                    clearStream = ToMemoryStream(xmlElement);
                    break;
                default:
                    throw new NotImplementedException("Clear text type not supported yet");
            }

            try
            {
                if (_logger?.IsEnabled(LogLevel.Debug) == true)
                {
                    long position = clearStream.Position;
                    using (var reader = new StreamReader(clearStream, Encoding.UTF8, true, 1024, true))
                        _logger.LogDebug("encrypted content: {0}", reader.ReadToEnd());
                    clearStream.Position = position;
                }
                using (var lease = sealers.Acquire(Tuple.Create(level, ClientCredentials.ClientCertificate.Certificate, Settings.Default.UseNativeCrypto),
                    identity => new DataSealerFactory(NullLoggerFactory.Instance, identity.Item3).Create(identity.Item1, identity.Item2)))
                using (Stream cypherStream = await lease.Value.SealAsync(clearStream, recepients).ConfigureAwait(false))
                {
                    return ToByteArray(cypherStream);
                }
            }
            finally
            {
                if (!(clearText is Stream)) clearStream.Dispose();
            }
        }

        private static byte[] ToByteArray(Stream stream)
        {
            if (stream is MemoryStream memoryStream && memoryStream.Position == 0) return memoryStream.ToArray();
            return new BinaryReader(stream).ReadBytes((int)(stream.Length - stream.Position));
        }

        protected ClearType Decrypt<ClearType>(byte[] cypherText) where ClearType : class
        {
            return DecryptAsync<ClearType>(cypherText).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        protected async Task<ClearType> DecryptAsync<ClearType>(byte[] cypherText) where ClearType : class
        {
            UnsealResult result;
            var stores = new[] { Store }.Concat(ExpiredStores).ToArray();
            using (var lease = unsealers.Acquire(Tuple.Create(stores, Settings.Default.UseNativeCrypto),
                identity => new DataUnsealerFactory(NullLoggerFactory.Instance, identity.Item2).Create(Level.B_Level, identity.Item1)))
            using (Stream cypherStream = new MemoryStream(cypherText))
            {
                result = await lease.Value.UnsealAsync(cypherStream).ConfigureAwait(false);
            }

            try
            {
                if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid)
                    throw new SecurityException("Clear text not valid");
                if (result.SecurityInformation.TrustStatus == TrustStatus.None)
                    throw new SecurityException("Clear text untrused");

                if (_logger?.IsEnabled(LogLevel.Debug) == true)
                {
                    using (var reader = new StreamReader(result.UnsealedData, Encoding.UTF8, true, 1024, true))
                        _logger.LogDebug("decrypted content: {0}", reader.ReadToEnd());
                    result.UnsealedData.Position = 0;
                }

                switch (typeof(ClearType))
                {
                    case Type ct when ct == typeof(Stream):
                        return result.UnsealedData as ClearType;
                    case Type ct when ct == typeof(byte[]):
                        using (result.UnsealedData) return ToByteArray(result.UnsealedData) as ClearType;
                    case Type ct when ct == typeof(XmlElement):
                        using (result.UnsealedData) return ToXmlElement(result.UnsealedData) as ClearType;
                    default:
                        throw new NotImplementedException("Clear text type not supported yet");
                }
            }
            catch
            {
                result.UnsealedData?.Dispose();
                throw;
            }
        }
    }
}
