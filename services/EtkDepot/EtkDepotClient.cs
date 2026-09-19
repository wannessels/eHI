using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Egelke.EHealth.Client.Services.EtkDepot
{
    public class EtkDepotClient : ServiceClient<EtkDepotPortType>
    {


        public EtkDepotClient(EndpointAddress remoteAddress, ILogger<EtkDepotClient> logger = null)
            : base(new BasicHttpsBinding(), remoteAddress, logger)
        {

        }

        public EncryptionToken[] GetEtk(params IdentifierType[] searchCriteria) => GetEtkAsync(searchCriteria).ConfigureAwait(false).GetAwaiter().GetResult();

        public Task<EncryptionToken[]> GetEtkAsync(params IdentifierType[] searchCriteria)
            => GetEtkAsync(CancellationToken.None, searchCriteria);

        public Task<EncryptionToken[]> GetEtkAsync(CancellationToken cancellationToken, params IdentifierType[] searchCriteria)
            => RunOperationAsync(() => GetEtkCoreAsync(searchCriteria), cancellationToken);

        private async Task<EncryptionToken[]> GetEtkCoreAsync(IdentifierType[] searchCriteria)
        {
            var req = BuildRequest(searchCriteria);
            return ParseResponse((await SendAsync(() => Channel.GetEtkAsync(req)).ConfigureAwait(false))?.GetEtkResponse);
        }

        private GetEtkRequest1 BuildRequest(IdentifierType[] searchCriteria)
        {
            _logger?.LogInformation("Retreiving Etk(s) from depot, # criteria={0}", searchCriteria?.Length);
            foreach (IdentifierType identifier in searchCriteria)
            {
                _logger?.LogDebug("Retreiving Etk from depot for {0}={1}, {2}",
                    identifier.Type, identifier.Value, identifier.ApplicationID);
            }
            return new GetEtkRequest1()
            {
                GetEtkRequest = new GetEtkRequest()
                {
                    SearchCriteria = searchCriteria
                }
            };
        }

        private EncryptionToken[] ParseResponse(GetEtkResponse rsp)
        {
            _logger?.LogInformation("Retrived Etk(s) from depot: Status={0}, Message=\"{1}\", # items={2}",
                rsp?.Status?.Code, rsp?.Status?.Message?.FirstOrDefault()?.Value, rsp?.Items?.Length);

            if (rsp?.Status?.Code != "200")
            {
                _logger?.LogWarning("Failed to obtain ETK, Status Error returned {0}: {1}", rsp?.Status?.Code,
                    String.Join(", ", rsp?.Status?.Message?.Select(m => m?.Value)));
                throw new ServiceException(rsp?.Status?.Code, rsp?.Status?.Message?.FirstOrDefault()?.Value);
            }
            var errors = rsp.Items
                .OfType<ErrorType1>()
                .ToList();
            foreach (var error in errors) {
                _logger?.LogWarning("Failed to obtain ETK, Message Error returned {0}: {1}", error.Code, error.Message);
            }
            if (errors.Any())
            {
                var error = errors.First();
                throw new ServiceException(error.Code, error.Message);
            }

            for (int i = 0; i < rsp.Items.Length; i++)
            {
                if (rsp.Items[i] is MatchingEtk matching)
                {
                    IdentifierType criterial = rsp.GivenSearchCriteria[i];
                    _logger?.LogWarning("criteria returned multiple matches {0}={1}, {2}", criterial.Type, criterial.Value, criterial.ApplicationID);
                    throw new MultiMatchException(criterial, matching.Identifier);
                }
            }

            return rsp.Items
                .Cast<byte[]>()
                .Select(i => new EncryptionToken(i))
                .ToArray();
        }
    }
}


