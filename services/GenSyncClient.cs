using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services
{
    public class GenSyncClient<Port> : ServiceClient<Port> where Port : class
    {
        private const string CIN_ENC_NS = "urn:be:cin:encrypted";

        public LicenseType License { get; set; }

        public CareProviderType CareProvider { get; set; }

        public bool IsTest { get; set; } = false;

        protected GenSyncClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<GenSyncClient<Port>> logger = null)
            : base(store, binding, remoteAddress, logger)
        {

        }
            

        private sealed class DecryptedContent
        {
            public DecryptedContent(byte[] body, string contentType)
            {
                Body = body;
                ContentType = contentType;
            }

            public byte[] Body { get; }
            public string ContentType { get; }
        }

        protected SendRequest CreateRequest<SendRequest>(String inputRef, XmlElement value, EncryptionType? etee = null) where SendRequest : SendRequestType, new()
        {
            return CreateRequest<SendRequest>(inputRef, "text/xml", ToByteArray(value), etee);
        }

        protected Task<SendRequest> CreateRequestAsync<SendRequest>(String inputRef, XmlElement value, EncryptionType? etee = null) where SendRequest : SendRequestType, new()
        {
            return CreateRequestAsync<SendRequest>(inputRef, "text/xml", ToByteArray(value), etee);
        }

        protected SendRequest CreateRequest<SendRequest>(String inputRef, String contentType, byte[] value, EncryptionType? etee = null) where SendRequest : SendRequestType, new()
        {
            switch (etee)
            {
                case null:
                    return BuildRequest<SendRequest>(inputRef, value, contentType, null);
                case EncryptionType.EncryptedForKnownBED:
                    return BuildRequest<SendRequest>(inputRef, EncryptForBed(inputRef, value, contentType), "text/plain", "encryptedForKnownBED");
                default:
                    throw new NotImplementedException("Encryption type not supported yet");
            }
        }

        protected async Task<SendRequest> CreateRequestAsync<SendRequest>(String inputRef, String contentType, byte[] value, EncryptionType? etee = null) where SendRequest : SendRequestType, new()
        {
            switch (etee)
            {
                case null:
                    return BuildRequest<SendRequest>(inputRef, value, contentType, null);
                case EncryptionType.EncryptedForKnownBED:
                    return BuildRequest<SendRequest>(inputRef, await EncryptForBedAsync(inputRef, value, contentType).ConfigureAwait(false), "text/plain", "encryptedForKnownBED");
                default:
                    throw new NotImplementedException("Encryption type not supported yet");
            }
        }

        private SendRequest BuildRequest<SendRequest>(String inputRef, byte[] blobValue, string blobContentType, string contentEncryption) where SendRequest : SendRequestType, new()
        {
            var req = new SendRequest()
            {
                Id = "_" + Guid.NewGuid().ToString(),
                CommonInput = new CommonInputType()
                {
                    InputReference = inputRef,
                    Request = new RequestType1()
                    {
                        IsTest = IsTest,
                    },
                    Origin = new OriginType()
                    {
                        Package = new PackageType()
                        {
                            License = License
                        },
                        CareProvider = CareProvider ?? Sender?.ToCareProvider()
                    }
                },
                Detail = new BlobType()
                {
                    ContentType = blobContentType,
                    ContentEncoding = "none", //todo::support encodings
                    Value = blobValue,
                    ContentEncryption = contentEncryption    
                }
                //todo::support xades-t
            };

            return req;
        }

        protected Response HandleReturn<Response>(ResponseReturnType rsp) where Response : class
        {
            LogReturn(rsp);

            DecryptedContent content;
            switch (rsp?.Detail?.ContentEncryption)
            {
                case null:
                    content = new DecryptedContent(rsp?.Detail?.Value, rsp?.Detail?.ContentType);
                    break;
                case "encryptedForKnownRecipient":
                    CheckEncryptedContentType(rsp);
                    content = DecryptForKnown(rsp.Detail.Value);
                    break;
                default:
                    throw new NotImplementedException("encryption is not yet supported");
            }

            return ToResponse<Response>(rsp, content);
        }

        protected async Task<Response> HandleReturnAsync<Response>(ResponseReturnType rsp) where Response : class
        {
            LogReturn(rsp);

            DecryptedContent content;
            switch (rsp?.Detail?.ContentEncryption)
            {
                case null:
                    content = new DecryptedContent(rsp?.Detail?.Value, rsp?.Detail?.ContentType);
                    break;
                case "encryptedForKnownRecipient":
                    CheckEncryptedContentType(rsp);
                    content = await DecryptForKnownAsync(rsp.Detail.Value).ConfigureAwait(false);
                    break;
                default:
                    throw new NotImplementedException("encryption is not yet supported");
            }

            return ToResponse<Response>(rsp, content);
        }

        private void LogReturn(ResponseReturnType rsp)
        {
            _logger?.LogInformation("Received response for {0} with out-ref {1} and nip-ref {2}",
                rsp.CommonOutput.InputReference,
                rsp?.CommonOutput?.OutputReference,
                rsp?.CommonOutput?.NIPReference);
        }

        private static void CheckEncryptedContentType(ResponseReturnType rsp)
        {
            //check content type, should be text/plain (a somewhat dubious choice)
            if (rsp?.Detail?.ContentType != "text/plain") throw new InvalidOperationException("content type not supported for encrypted content: " + rsp?.Detail?.ContentType);
        }

        private Response ToResponse<Response>(ResponseReturnType rsp, DecryptedContent content) where Response : class
        {
            if (_logger?.IsEnabled(LogLevel.Debug) == true)
            {
                _logger.LogDebug("Received response for {0}: {1}",
                    rsp.CommonOutput.InputReference,
                    Encoding.UTF8.GetString(content.Body));
            }

            switch (typeof(Response))
            {
                case Type r when r == typeof(XmlElement):
                    if (content.ContentType != "text/xml" && content.ContentType != "application/xml") throw new InvalidOperationException("content type not matching the requested return type: " + content.ContentType);
                    return ToXmlElement(content.Body) as Response;
                default:
                    throw new NotImplementedException("Only text/xml responses are supported at this moment");
            }
        }

        protected byte[] EncryptForBed(String inputRef, byte[] clearText, string contentType)
        {
            using (var clear = BuildKnownContent(inputRef, clearText, contentType))
            {
                return EncryptForService(clear, Level.B_Level);
            }
        }

        protected async Task<byte[]> EncryptForBedAsync(String inputRef, byte[] clearText, string contentType)
        {
            using (var clear = BuildKnownContent(inputRef, clearText, contentType))
            {
                return await EncryptForServiceAsync(clear, Level.B_Level).ConfigureAwait(false);
            }
        }

        private MemoryStream BuildKnownContent(String inputRef, byte[] clearText, string contentType)
        {
            XNamespace ns_e = "urn:be:cin:encrypted";
            var ekc = new XDocument(
                    new XElement(ns_e + "EncryptedKnownContent",
                        new XElement(ns_e + "BusinessContent",
                            new XAttribute("id", inputRef),
                            new XAttribute("ContentType", contentType),
                            new XAttribute("ContentEncoding", "none"),
                            Convert.ToBase64String(clearText)
                        )
                        //todo::support xades
                    )
            );
            //injectreply to etk as the first element if needed.
            if (Sender?.Etk != null) {
                ekc.Root.AddFirst(
                    new XElement(ns_e + "Reply-to-Etk",
                            Sender.Etk.GetEncodedAsString()
                        )
                );
            }
            return ToMemoryStream(ekc);
        }

        protected byte[] DecryptForKnown(byte[] cypherText, out string contentType)
        {
            DecryptedContent content = DecryptForKnown(cypherText);
            contentType = content.ContentType;
            return content.Body;
        }

        private DecryptedContent DecryptForKnown(byte[] cypherText)
        {
            return ParseKnownContent(Decrypt<XmlElement>(cypherText));
        }

        private async Task<DecryptedContent> DecryptForKnownAsync(byte[] cypherText)
        {
            return ParseKnownContent(await DecryptAsync<XmlElement>(cypherText).ConfigureAwait(false));
        }

        private static DecryptedContent ParseKnownContent(XmlElement clearEl)
        {
            XmlNamespaceManager encMngr = new XmlNamespaceManager(clearEl.OwnerDocument.NameTable);
            encMngr.AddNamespace("e", CIN_ENC_NS);

            string businessContentStr = clearEl.SelectSingleNode("/e:EncryptedKnownContent/e:BusinessContent", encMngr)?.InnerText;
            string contentType = clearEl.SelectSingleNode("/e:EncryptedKnownContent/e:BusinessContent/@ContentType", encMngr)?.Value;
            //todo::support content encoding
            return new DecryptedContent(Convert.FromBase64String(businessContentStr), contentType);
        }

    }
}
