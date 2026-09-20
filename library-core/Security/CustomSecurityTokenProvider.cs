/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System.Diagnostics;
#if NETSTANDARD2_0
using X509SecurityToken = Egelke.EHealth.Client.Compatibility.CertificateProofToken;
#endif
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Threading;
using Egelke.EHealth.Client.Pki;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Sts.WsTrust200512;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom WCF Token Provider for eHealth.
    /// </summary>
    public class CustomSecurityTokenProvider : SecurityTokenProvider
    {
        private readonly ILogger<CustomSecurity> _logger;

        private readonly WSS _wss;

        private readonly SecurityTokenRequirement _tokenRequirement;

        private readonly CustomIssuedSecurityTokenParameters _tokenParams;

        private readonly X509Certificate2 _idCert;

        private static readonly ConditionalWeakTable<IMemoryCache, AsyncSingleFlight<string, SecurityToken>> flights = new ConditionalWeakTable<IMemoryCache, AsyncSingleFlight<string, SecurityToken>>();

        private static readonly ConditionalWeakTable<X509Certificate2, GenericXmlSecurityToken> x509Tokens = new ConditionalWeakTable<X509Certificate2, GenericXmlSecurityToken>();

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="tokenRequirement">requirements for the provided token</param>
        /// <param name="idCert">the subjects certificate to request a token for</param>
        public CustomSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, X509Certificate2 idCert, ILogger<CustomSecurity> logger)
        {
            _logger = logger;
            _wss = (WSS)tokenRequirement.Properties["wss"];
            _tokenRequirement = tokenRequirement;
            _tokenRequirement.TryGetProperty<CustomIssuedSecurityTokenParameters>(CustomIssuedSecurityTokenParameters.IssuedSecurityTokenParametersProperty, out _tokenParams);
            _idCert = idCert;
        }

        /// <summary>
        /// Obtains a token.
        /// </summary>
        /// <remarks>
        /// Supports both X509Certificate and SAML (v1.1) tokens.
        /// <para>
        /// Creates a X509Certificate token as a GenericXmlSecurityToken so it can be used by the custom applied message.
        /// </para>
        /// <para>
        /// Looks for the correct SAML token in the cache; if not found requests a new token from the STS and adds it to
        /// the cache.
        /// </para>
        /// </remarks>
        /// <param name="timeout">timeout to resprect</param>
        /// <returns>A generic xml security token that can be an X509Certificate or a SAML-Assertion with HOK</returns>
        /// <exception cref="NotSupportedException"></exception>
        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            switch (_tokenRequirement.TokenType)
            {
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate":
                    return CreateX509CertificateToken();
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/Saml":
                    return GetSamlHokToken(timeout);
                default:
                    throw new NotSupportedException("Requested token type " + _tokenRequirement.TokenType + " not supported yet");
            }
        }

        /// <summary>
        /// Create a token directly from the subject X509Certificate2.
        /// </summary>
        /// <remarks>
        /// WCF has excelent build in support for this, but returns a different token type that is internal on certain
        /// frameworks and can therefor not be used by the custom applied message implementation. The token is built
        /// once per certificate and shared by every provider and request.
        /// </remarks>
        /// <returns>The generic xml version of the token</returns>
        protected SecurityToken CreateX509CertificateToken() => x509Tokens.GetValue(_idCert, BuildX509CertificateToken);

        private GenericXmlSecurityToken BuildX509CertificateToken(X509Certificate2 certificate)
        {
            String id = "urn:uuid:" + Guid.NewGuid().ToString();

            XmlDocument doc = new XmlDocument();

            XmlElement bst = doc.CreateElement(_wss.SecExtPrefix, "BinarySecurityToken", WSS.SECEXT10_NS);
            XmlAttribute bstId = doc.CreateAttribute(_wss.UtilityPrefix, "Id", WSS.UTILITY_NS);
            bstId.Value = id;
            bst.Attributes.Append(bstId);
            XmlAttribute bstValueType = doc.CreateAttribute("ValueType");
            bstValueType.Value = WSS.TOKEN_PROFILE_X509_NS + "#X509v3";
            bst.Attributes.Append(bstValueType);
            XmlAttribute bstEncodingType = doc.CreateAttribute("EncodingType");
            bstEncodingType.Value = WSS.NS + "#Base64Binary";
            bst.Attributes.Append(bstEncodingType);
            XmlText bstValue = doc.CreateTextNode(Convert.ToBase64String(certificate.RawData));
            bst.AppendChild(bstValue);

            XmlElement str = doc.CreateElement(_wss.SecExtPrefix, "SecurityTokenReference", WSS.SECEXT10_NS);
            XmlElement reference = doc.CreateElement(_wss.SecExtPrefix, "Reference", WSS.SECEXT10_NS);
            XmlAttribute uri = doc.CreateAttribute("URI");
            uri.Value = "#" + id;
            reference.Attributes.Append(uri);
            XmlAttribute valueType = doc.CreateAttribute("ValueType");
            valueType.Value = WSS.TOKEN_PROFILE_X509_NS + "#X509v3";
            reference.Attributes.Append(valueType);
            str.AppendChild(reference);

            return new GenericXmlSecurityToken(
                bst,
                new X509SecurityToken(certificate),
                certificate.NotBefore.ToUniversalTime(),
                certificate.NotAfter.ToUniversalTime(),
                new GenericXmlSecurityKeyIdentifierClause(str),
                null,
                null
                );
        }

        /// <summary>
        /// Obtains a SAML v1.1 token with HOK, first looks in the cache and if not found obtains a new one from the STS.
        /// </summary>
        /// <param name="timeout">The timeout to respect when obtaining the token from the STS</param>
        /// <returns>The generic xml version of the token</returns>
        protected SecurityToken GetSamlHokToken(TimeSpan timeout)
        {
            return GetSamlHokTokenAsync(timeout).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>Prepares a token before WCF serializes the message.</summary>
        public async Task<GenericXmlSecurityToken> PrepareTokenAsync(TimeSpan timeout)
        {
            switch (_tokenRequirement.TokenType)
            {
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate":
                    return (GenericXmlSecurityToken)CreateX509CertificateToken();
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/Saml":
                    return (GenericXmlSecurityToken)await GetSamlHokTokenAsync(timeout).ConfigureAwait(false);
                default:
                    throw new NotSupportedException("Requested token type " + _tokenRequirement.TokenType + " not supported");
            }
        }

        private async Task<SecurityToken> GetSamlHokTokenAsync(TimeSpan timeout)
        {
            var cache = _tokenParams.Cache;
            var tokenId = _tokenParams.ToId(_idCert);
            var token = cache.Get<SecurityToken>(tokenId);
            if (IsUsable(token)) return token;
            var flight = flights.GetValue(cache, _ => new AsyncSingleFlight<string, SecurityToken>());
            using (var waiter = CancellationTokenSource.CreateLinkedTokenSource(OperationScope.Cancellation))
            {
                waiter.CancelAfter(OperationScope.LimitTimeout(timeout));
                try
                {
                    return await flight.RunAsync(tokenId, async cancellationToken =>
                    {
                        var flightTimeout = _tokenParams.IssuerBinding?.SendTimeout ?? TimeSpan.FromMinutes(1);
                        using (var scope = new OperationScope(cancellationToken, flightTimeout, inherit: false))
                        {
                            token = cache.Get<SecurityToken>(tokenId);
                            if (IsUsable(token)) return token;
                            string type = token == null ? "issue" : "renew"; long started = Stopwatch.GetTimestamp(); string outcome = "ok";
                            try
                            {
                                token = token == null
                                ? await CreateSamlHokTokenAsync(flightTimeout).ConfigureAwait(false)
                                : await RenewSamlHokTokenAsync(token, flightTimeout).ConfigureAwait(false);
                            }
                            catch (Exception error) { outcome = EHealthMetrics.Outcome(error); throw; }
                            finally { EHealthMetrics.Record(EHealthMetrics.StsRequests, EHealthMetrics.StsRequestDuration, started, new TagList { { "type", type }, { "outcome", outcome } }); }
                            cache.Set(tokenId, token, new MemoryCacheEntryOptions
                            {
                                Size = 1,
                                AbsoluteExpiration = token.ValidTo.AddHours(1)
                            });
                            return token;
                        }
                    }, waiter.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!OperationScope.Cancellation.IsCancellationRequested)
                { throw new TimeoutException("Token acquisition exceeded the operation deadline"); }
            }
        }

        private static bool IsUsable(SecurityToken token)
            => token != null && token.ValidTo >= DateTime.UtcNow.AddMinutes(5);

        /// <summary>Obtains a fresh token with a bounded STS operation.</summary>
        protected SecurityToken CreateSamlHokToken(TimeSpan timeout)
            => CreateSamlHokTokenAsync(timeout).ConfigureAwait(false).GetAwaiter().GetResult();

        /// <summary>Obtains a fresh token asynchronously.</summary>
        protected virtual async Task<SecurityToken> CreateSamlHokTokenAsync(TimeSpan timeout)
        {
            var deadline = new RequestDeadline(timeout);
            var client = CreateStsClient();
            try
            {
                return ParseAssertion(await client.RequestTicketAsync(_tokenParams.SessionCertificate,
                    _tokenParams.SessionDuration, _tokenParams.AuthClaims, deadline.Remaining).ConfigureAwait(false));
            }
            finally { await WsTrustClient.CloseOrAbortAsync(client, deadline).ConfigureAwait(false); }
        }

        private WsTrustClient CreateStsClient()
        {
            var client = new WsTrustClient(_tokenParams.IssuerBinding ?? new EhBinding(_logger), _tokenParams.IssuerAddress, _logger);
            client.ClientCredentials.ClientCertificate.Certificate = _idCert;
            if (_logger != null) client.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(_logger));
            return client;
        }

        /// <summary>Renews a token with a bounded STS operation.</summary>
        protected SecurityToken RenewSamlHokToken(SecurityToken previous, TimeSpan timeout)
            => RenewSamlHokTokenAsync(previous, timeout).ConfigureAwait(false).GetAwaiter().GetResult();

        /// <summary>Renews a token asynchronously.</summary>
        protected virtual async Task<SecurityToken> RenewSamlHokTokenAsync(SecurityToken previous, TimeSpan timeout)
        {
            var xmlToken = previous as GenericXmlSecurityToken ?? throw new ArgumentException("Previous token must be an XML token", nameof(previous));
            var deadline = new RequestDeadline(timeout);
            var client = CreateStsClient();
            try
            {
                return ParseAssertion(await client.RenewTicketAsync(_tokenParams.SessionCertificate,
                    xmlToken.TokenXml, deadline.Remaining).ConfigureAwait(false));
            }
            finally { await WsTrustClient.CloseOrAbortAsync(client, deadline).ConfigureAwait(false); }
        }
        private GenericXmlSecurityToken ParseAssertion(XmlElement assertion)
        {
            XmlDocument doc = assertion.OwnerDocument;
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(doc.NameTable);
            nsMngr.AddNamespace("s11", "urn:oasis:names:tc:SAML:1.0:assertion");

            string id = assertion.GetAttribute("AssertionID");
            string notBefore = assertion.SelectSingleNode("./s11:Conditions/@NotBefore", nsMngr).Value;
            string notOnOrAfter = assertion.SelectSingleNode("./s11:Conditions/@NotOnOrAfter", nsMngr).Value;

            XmlElement str = doc.CreateElement(_wss.SecExtPrefix, "SecurityTokenReference", WSS.SECEXT10_NS);
            XmlAttribute tokenType = doc.CreateAttribute("wsse11", "TokenType", WSS.SECEXT11_NS);
            tokenType.Value = WSS.TOKEN_PROFILE_SAML11_NS + "#SAMLV1.1";
            str.Attributes.Append(tokenType);
            XmlElement reference = doc.CreateElement(_wss.SecExtPrefix, "KeyIdentifier", WSS.SECEXT10_NS);
            XmlAttribute valueType = doc.CreateAttribute("ValueType");
            valueType.Value = WSS.TOKEN_PROFILE_SAML10_NS + "#SAMLAssertionID";
            reference.Attributes.Append(valueType);
            reference.AppendChild(doc.CreateTextNode(id));

            str.AppendChild(reference);

            return new GenericXmlSecurityToken(
                assertion,
                new X509SecurityToken(_tokenParams.SessionCertificate ?? _idCert),
                DateTime.Parse(notBefore),
                DateTime.Parse(notOnOrAfter),
                new GenericXmlSecurityKeyIdentifierClause(str),
                null,
                null
                );
        }
    }
}

