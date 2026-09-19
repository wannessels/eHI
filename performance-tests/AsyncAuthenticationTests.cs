using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Reflection;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Security;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Client.Sts.WsTrust200512;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

public class AsyncAuthenticationTests
{
    internal static GenericXmlSecurityToken Token(DateTime? expires = null)
    {
        var doc = new XmlDocument(); doc.LoadXml("<Assertion/>");
        return new GenericXmlSecurityToken(doc.DocumentElement, null, DateTime.UtcNow.AddMinutes(-1), expires ?? DateTime.UtcNow.AddHours(1), null, null, null);
    }

    [Fact]
    public void StsContractPairsSyncAndAsyncOperations()
    {
        var contract = ContractDescription.GetContract(typeof(IWsTrustPortFixed));
        Assert.Equal(2, contract.Operations.Count);
        Assert.All(contract.Operations, operation => Assert.NotNull(operation.TaskMethod));
    }

    [Fact]
    public async Task TokenMissesShareOneAsyncRequestAndFailuresCanRetry()
    {
        using (var cache = new MemoryCache(new MemoryCacheOptions()))
        {
            var requirement = new SecurityTokenRequirement { TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/Saml" };
            requirement.Properties["wss"] = WSS.Create(SecurityVersion.WSSecurity11);
            var parameters = new CustomIssuedSecurityTokenParameters(new AuthClaimSet(), null, TimeSpan.FromHours(1))
            { IssuerAddress = new EndpointAddress("https://example.invalid/sts"), Cache = cache };
            requirement.Properties["http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuedSecurityTokenParameters"] = parameters;
            var provider = new TestProvider(requirement);
            var calls = Enumerable.Range(0, 32).Select(_ => provider.PrepareTokenAsync(TimeSpan.FromSeconds(5))).ToArray();
            Assert.Equal(1, provider.Calls);
            Assert.All(calls, call => Assert.False(call.IsCompleted));
            provider.Completion.SetException(new InvalidOperationException("fixture"));
            foreach (var call in calls) await Assert.ThrowsAsync<InvalidOperationException>(() => call);
            provider.Completion = new TaskCompletionSource<SecurityToken>(TaskCreationOptions.RunContinuationsAsynchronously);
            var retry = provider.PrepareTokenAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(2, provider.Calls);
            provider.Completion.SetResult(Token());
            Assert.Same(await retry, await provider.PrepareTokenAsync(TimeSpan.FromSeconds(5)));
            Assert.Equal(2, provider.Calls);
        }
    }

    [Fact]
    public async Task RequestAwaitsTokenBeforeTransportAndPreservesApmState()
    {
        var inner = DispatchProxy.Create<IRequestChannel, StubChannel>();
        var stub = (StubChannel)(object)inner;
            var channel = new TestChannel(inner) { MessageSecurityVersion = SecurityVersion.WSSecurity11 };
        var completed = new TaskCompletionSource<IAsyncResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var state = new object();
        using (var message = Message.CreateMessage(MessageVersion.Soap11, "test"))
        {
            var pending = channel.BeginRequest(message, TimeSpan.FromSeconds(5), result => completed.SetResult(result), state);
            Assert.Same(state, pending.AsyncState);
            Assert.Equal(0, stub.Requests);
            Assert.False(pending.IsCompleted);
            channel.Completion.SetResult(Token());
            await completed.Task;
            using (var response = channel.EndRequest(pending)) Assert.NotNull(response);
            Assert.Equal(1, stub.Requests);
            Assert.True(stub.Timeout <= TimeSpan.FromSeconds(5));
        }
    }

    private sealed class TestProvider : CustomSecurityTokenProvider
    {
        internal int Calls;
        internal TaskCompletionSource<SecurityToken> Completion = new TaskCompletionSource<SecurityToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TestProvider(SecurityTokenRequirement requirement) : base(requirement, null, null) { }
        protected override Task<SecurityToken> CreateSamlHokTokenAsync(TimeSpan timeout) { Interlocked.Increment(ref Calls); return Completion.Task; }
    }
    private sealed class TestChannel : CustomSecurityRequestChannel
    {
        internal readonly TaskCompletionSource<GenericXmlSecurityToken> Completion = new TaskCompletionSource<GenericXmlSecurityToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TestChannel(IRequestChannel inner) : base(null, inner, new EndpointAddress("https://example.invalid"), new Uri("https://example.invalid")) { }
        protected override Task<GenericXmlSecurityToken> AcquireTokenAsync(TimeSpan timeout) => Completion.Task;
    }
    public class StubChannel : DispatchProxy
    {
        public int Requests;
        public TimeSpan Timeout;
        protected override object Invoke(MethodInfo method, object[] args)
        {
            if (method.Name == "BeginRequest")
            {
                Requests++; Timeout = (TimeSpan)args[1];
                Assert.NotNull(((CustomSecurityAppliedMessage)args[0]).PreparedToken);
                var result = new TaskCompletionSource<Message>(args[3]);
                result.SetResult(Message.CreateMessage(MessageVersion.Soap11, "response"));
                ((AsyncCallback)args[2])(result.Task);
                return result.Task;
            }
            if (method.Name == "EndRequest") return ((Task<Message>)args[0]).GetAwaiter().GetResult();
            throw new NotSupportedException(method.Name);
        }
    }
}
