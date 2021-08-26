using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestHealthCheck
    {
        private const string HEALTHY_CONTENT = @"{""stat"": ""OK"", ""response"": {""timestamp"": ""1629837896""}}";
        private const string UNHEALTHY_CONTENT = @"{""stat"": ""FAIL"", ""response"": {""code"": ""40301"", ""timestamp"": ""1629837896"", ""message"": ""ohnoes"", ""message_detail"": ""ohnoes""}}";

        private const string CLIENT_ID = "client id";
        private const string CLIENT_SECRET = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private const string API_HOST = "fake.api.host";

        [SetUp]
        public void Setup()
        {
        }

        private static Client MakeClient(HttpMessageHandler handler)
        {
            return new Client(CLIENT_ID, CLIENT_SECRET, API_HOST, handler);
        }

        [Test]
        public async Task TestSuccess()
        {
            Client client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(HEALTHY_CONTENT)));
            bool healthy = await client.DoHealthCheck();
            Assert.True(healthy);
        }

        [Test]
        public async Task TestHttpException()
        {
            Client client = MakeClient(new HttpExcepter());
            bool healthy = await client.DoHealthCheck();
            Assert.False(healthy);
        }

        [Test]
        public async Task TestUnhealthyStat()
        {
            Client client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(UNHEALTHY_CONTENT)));
            bool healthy = await client.DoHealthCheck();
            Assert.False(healthy);
        }

        [Test]
        public async Task TestBadStatusCode()
        {
            Client client = MakeClient(new HttpResponder(HttpStatusCode.BadRequest, new StringContent(UNHEALTHY_CONTENT)));
            bool healthy = await client.DoHealthCheck();
            Assert.False(healthy);
        }
    }

    // TODO these will be useful for the other tests of API functionality (once they exist) so I'll need to move these
    internal class HttpExcepter : HttpMessageHandler
    {
        public HttpExcepter()
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("TODO");  // TODO any need to customize the message?  or exception type?
        }
    }

    internal class HttpResponder : HttpMessageHandler
    {
        private readonly HttpStatusCode statusCode;
        private readonly HttpContent content;

        public HttpResponder(HttpStatusCode statusCode, HttpContent content)
        {
            this.statusCode = statusCode;
            this.content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage() { StatusCode = statusCode, Content = content });
        }
    }
}
