using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DuoUniversal.Tests
{
    public class ClientTestBase
    {
        protected const string CLIENT_ID = "client id";
        protected const string CLIENT_SECRET = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        protected const string API_HOST = "fake.api.host";
        protected const string REDIRECT_URI = "https://fake.com/fake";
    }

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
