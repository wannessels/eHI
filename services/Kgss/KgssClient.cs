using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.Kgss
{
    public class KgssClient : ServiceClient<KgssPortType>
    {
        internal static readonly XNamespace NS_KGSS = "urn:be:fgov:ehealth:etee:kgss:1_0:protocol";

        public KgssClient(EHealthP12 store, EndpointAddress remoteAddress, ILogger<KgssClient> logger = null)
            : this(store, new BasicHttpsBinding(), remoteAddress, logger)
        { }

        public KgssClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<KgssClient> logger = null)
            : base(store, binding, remoteAddress, logger)
        {
            Service = new PartyInfo()
            {
                Cbe = "0809394427",
                Application = "KGSS"
            };
        }

        public SecretKey GetNewKey(params CredentialType[] allowed) => GetNewKeyAsync(allowed).ConfigureAwait(false).GetAwaiter().GetResult();

        public Task<SecretKey> GetNewKeyAsync(params CredentialType[] allowed) => GetNewKeyAsync(CancellationToken.None, allowed);

        public Task<SecretKey> GetNewKeyAsync(CancellationToken cancellationToken, params CredentialType[] allowed)
            => RunOperationAsync(() => GetNewKeyCoreAsync(allowed), cancellationToken);

        private async Task<SecretKey> GetNewKeyCoreAsync(CredentialType[] allowed)
        {
            var req = BuildGetNewKeyRequest(await EncryptForServiceAsync(CreateGetNewKeyRequestContent(allowed)).ConfigureAwait(false), allowed);
            var rsp = (await SendAsync(() => Channel.GetNewKeyAsync(req)).ConfigureAwait(false))?.GetNewKeyResponse;
            CheckGetNewKeyResponse(rsp);
            return ParseGetNewKeyResponseContent(await DecryptAsync<XmlElement>(rsp.SealedNewKeyResponse.SealedContent).ConfigureAwait(false));
        }

        private GetNewKeyRequest1 BuildGetNewKeyRequest(byte[] sealedContent, CredentialType[] allowed)
        {
            _logger.LogInformation("Requesting New Key from KGSS, for {0} allowed", allowed?.Length);
            return new GetNewKeyRequest1()
            {
                GetNewKeyRequest = new GetNewKeyRequest()
                {
                    SealedNewKeyRequest = new SealedContentType()
                    {
                        SealedContent = sealedContent
                    }
                }
            };
        }

        private void CheckGetNewKeyResponse(GetNewKeyResponse rsp)
        {
            if (rsp?.Status?.Code != "200")
            {
                _logger.LogWarning("Failed to retrieve New Key from KGSS {0}: {1}", rsp?.Status?.Code, rsp?.Status?.Message);
                foreach(var error in rsp.Error)
                {
                    _logger.LogWarning("Error detail for New Key from KGSS {0}: {1}", error.Code, error.Message?.FirstOrDefault()?.Value);
                }
                throw new ServiceException(rsp?.Status?.Code, rsp?.Status?.Message);
            }
            CheckErrors(rsp?.Error);
            _logger.LogInformation("Received New Key from KGSS with response id {0}", rsp?.Id);
        }

        public SecretKey GetKey(byte[] id) => GetKeyAsync(id).ConfigureAwait(false).GetAwaiter().GetResult();

        public Task<SecretKey> GetKeyAsync(byte[] id) => GetKeyAsync(id, CancellationToken.None);

        public Task<SecretKey> GetKeyAsync(byte[] id, CancellationToken cancellationToken)
            => RunOperationAsync(() => GetKeyCoreAsync(id), cancellationToken);

        private async Task<SecretKey> GetKeyCoreAsync(byte[] id)
        {
            var req = BuildGetKeyRequest(await EncryptForServiceAsync(CreateGetKeyRequestContent(id)).ConfigureAwait(false), id);
            var rsp = (await SendAsync(() => Channel.GetKeyAsync(req)).ConfigureAwait(false))?.GetKeyResponse;
            CheckGetKeyResponse(rsp);
            return new SecretKey(id, ParseGetKeyResponseContent(await DecryptAsync<XmlElement>(rsp.SealedKeyResponse.SealedContent).ConfigureAwait(false)));
        }

        private GetKeyRequest1 BuildGetKeyRequest(byte[] sealedContent, byte[] id)
        {
            _logger.LogInformation("Requesting Key from KGSS, with id {0}", Convert.ToBase64String(id));
            return new GetKeyRequest1()
            {
                GetKeyRequest = new GetKeyRequest()
                {
                    SealedKeyRequest = new SealedContentType()
                    {
                        SealedContent = sealedContent
                    }
                }
            };
        }

        private void CheckGetKeyResponse(GetKeyResponse rsp)
        {
            if (rsp?.Status?.Code != "200")
            {
                _logger.LogWarning("Failed to retrieve Key from KGSS {0}: {1}", rsp?.Status?.Code, rsp?.Status?.Message);
                foreach (var error in rsp.Error)
                {
                    _logger.LogWarning("Error detailfor Key from KGSS {0}: {1}", error.Code, error.Message?.FirstOrDefault()?.Value);
                }
                throw new ServiceException(rsp?.Status?.Code, rsp?.Status?.Message);
            }
            CheckErrors(rsp?.Error);
            _logger.LogInformation("Received Key from KGSS with response id {0}", rsp?.Id);
        }

        private void CheckErrors(ErrorType2[] errors)
        {
            if (errors == null) return;
            foreach (var error in errors)
            {
                _logger?.LogWarning("Failed to obtain ETK, Message Error returned {0}: {1}", error.Code, error.Message);
            }
            if (errors.Length > 0)
            {
                var error = errors[0];
                throw new ServiceException(error.Code, error?.Message?.Length > 0 ? error.Message[0]?.Value : null);
            }
        }

        protected XmlElement CreateGetNewKeyRequestContent(CredentialType[] allowed)
        {
            var doc = new XDocument(
                new XElement(NS_KGSS + "GetNewKeyRequestContent",
                    allowed.Select(c => c.ToXElement(CredentialType.ROOTNAME_ALLOWED)),
                    new XElement(NS_KGSS + "ETK", Sender.Etk.GetEncodedAsString())
                    )
                );
            return ToXmlElement(doc);
        }

        protected XmlElement CreateGetKeyRequestContent(byte[] id)
        {
            var doc = new XDocument(
                new XElement(NS_KGSS + "GetKeyRequestContent",
                    new XElement(NS_KGSS + "KeyIdentifier", Convert.ToBase64String(id)),
                    new XElement(NS_KGSS + "ETK", Sender.Etk.GetEncodedAsString())
                    )
                );
            return ToXmlElement(doc);
        }

        protected SecretKey ParseGetNewKeyResponseContent(XmlElement rsp)
        {
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(rsp.OwnerDocument.NameTable);
            nsMngr.AddNamespace("kgss", NS_KGSS.NamespaceName);

            string id = rsp.SelectSingleNode("/kgss:GetNewKeyResponseContent/kgss:NewKeyIdentifier", nsMngr)?.InnerText;
            string value = rsp.SelectSingleNode("/kgss:GetNewKeyResponseContent/kgss:NewKey", nsMngr)?.InnerText;

            if (String.IsNullOrEmpty(id) || String.IsNullOrEmpty(value))
                throw new ArgumentException("No id or value found in the GetNewKeyResponseContent message", nameof(rsp));

            return new SecretKey(id, value);
        }

        protected byte[] ParseGetKeyResponseContent(XmlElement rsp)
        {
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(rsp.OwnerDocument.NameTable);
            nsMngr.AddNamespace("kgss", NS_KGSS.NamespaceName);

            var keyString = rsp.SelectSingleNode("/kgss:GetKeyResponseContent/kgss:Key", nsMngr)?.InnerText;
            return keyString != null ? Convert.FromBase64String(keyString) : null;
        }

    }
}


