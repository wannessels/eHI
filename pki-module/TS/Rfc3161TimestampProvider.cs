/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
 *  Copyright (C) 2012 I.M. vzw
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.Pkcs;
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Time-stamp provided via the RFC3161 protocol.
    /// </summary>
    /// <remarks>
    /// Get a time-stamp via the HTTP protocol.
    /// </remarks>
    public class Rfc3161TimestampProvider : ITimestampProviderAsync
    {
        private static readonly TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");
        private static readonly HttpClient http = new HttpClient() { Timeout = System.Threading.Timeout.InfiniteTimeSpan };

        private Uri address;

        /// <summary>
        /// Maximum time to wait for the TSA, defaults to 10 seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Constructor that has the Fedict TSA as destination.
        /// </summary>
        /// <remarks>
        /// You may only use this when you have the explicit agreement of Fedict. 
        /// </remarks>
        public Rfc3161TimestampProvider()
        {
            address = new Uri("http://tsa.belgium.be/connect");
        }

        /// <summary>
        /// Constructor that accept the address of the TSA.
        /// </summary>
        /// <param name="address">The url of the TSA</param>
        public Rfc3161TimestampProvider(Uri address)
        {
            this.address = address;
        }

        /// <summary>
        /// Gets a time-stamp of the provided address via the RFC3161.
        /// </summary>
        /// <param name="hash">The has to get the time-stamp from</param>
        /// <param name="digestMethod">The algorithm used to calculate the hash</param>
        /// <returns>The time-stamp token in binary (encoded) format</returns>
        /// <exception cref="WebException">When the TSA returned a http-error</exception>
        /// <exception cref="TspValidationException">When the TSA returns an invalid time-stamp response</exception>
        public byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            return GetTimestampFromDocumentHashAsync(hash, digestMethod).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets a time-stamp of the provided address via the RFC3161.
        /// </summary>
        /// <param name="hash">The has to get the time-stamp from</param>
        /// <param name="digestMethod">The algorithm used to calculate the hash</param>
        /// <returns>The time-stamp token in binary (encoded) format</returns>
        /// <exception cref="WebException">When the TSA returned a http-error</exception>
        /// <exception cref="TspValidationException">When the TSA returns an invalid time-stamp response</exception>
        public Task<byte[]> GetTimestampFromDocumentHashAsync(byte[] hash, string digestMethod)
            => GetTimestampFromDocumentHashAsync(hash, digestMethod, CancellationToken.None);

        /// <summary>Gets a timestamp under the shared operation policy with caller cancellation.</summary>
        public Task<byte[]> GetTimestampFromDocumentHashAsync(byte[] hash, string digestMethod, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => GetTimestampCoreAsync(hash, digestMethod), cancellationToken);

        private async Task<byte[]> GetTimestampCoreAsync(byte[] hash, string digestMethod)
        {
            Rfc3161TimestampRequest tspReq = CreateRfc3161RequestBody(hash, digestMethod);
            byte[] tsprBytes = tspReq.Encode();
            trace.TraceEvent(TraceEventType.Information, 0, "retrieving time-stamp of {0} from {1}", Convert.ToBase64String(hash), address);

            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(OperationScope.Cancellation))
            using (var content = new ByteArrayContent(tsprBytes))
            {
                cts.CancelAfter(OperationScope.LimitTimeout(Timeout));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
                using (HttpResponseMessage response = await http.PostAsync(address, content, cts.Token).ConfigureAwait(false))
                {
                    CheckRfc3161WebResponse(response);
                    byte[] body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                    return ParseRfc3161ResponseBody(body, tspReq);
                }
            }
        }

        private static readonly Dictionary<string, string> DigestOids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "http://www.w3.org/2000/09/xmldsig#sha1", "1.3.14.3.2.26" },
            { "http://www.w3.org/2001/04/xmlenc#sha256", "2.16.840.1.101.3.4.2.1" },
            { "http://www.w3.org/2001/04/xmldsig-more#sha384", "2.16.840.1.101.3.4.2.2" },
            { "http://www.w3.org/2001/04/xmlenc#sha512", "2.16.840.1.101.3.4.2.3" },
        };

        private static string ToDigestOid(string digestMethod)
        {
            if (DigestOids.TryGetValue(digestMethod, out string oid)) return oid;
            using (var algorithm = CryptoConfig.CreateFromName(digestMethod) as IDisposable)
            {
                return CryptoConfig.MapNameToOID(algorithm.GetType().ToString());
            }
        }

        private Rfc3161TimestampRequest CreateRfc3161RequestBody(byte[] hash, string digestMethod)
            => Rfc3161TimestampRequest.CreateFromHash(hash, CryptoEncoding.HashName(ToDigestOid(digestMethod)), requestSignerCertificates: true);
        private void CheckRfc3161WebResponse(HttpResponseMessage webResponse)
        {
            if (webResponse.StatusCode != HttpStatusCode.OK
                || webResponse.Content?.Headers.ContentType?.MediaType != "application/timestamp-reply")
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status or content for time-stamp reply: {0}", webResponse.ReasonPhrase);
                throw new ApplicationException("Response with invalid status or content type of the TSA: " + webResponse.ReasonPhrase);
            }
        }

        private byte[] ParseRfc3161ResponseBody(byte[] body, Rfc3161TimestampRequest request)
        {
            var token = request.ProcessResponse(body, out int consumed);
            if (consumed != body.Length) throw new CryptographicException("Trailing timestamp response data");
            return token.GetEncoded();
        }
    }
}