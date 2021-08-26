using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;

namespace DuoUniversal
{
    public class Client
    {
        internal const int MINIMUM_STATE_LENGTH = 22;
        internal const int DEFAULT_STATE_LENGTH = 36;
        internal const int MAXIMUM_STATE_LENGTH = 1024;

        private const string HEALTH_CHECK_ENDPOINT = "https://{0}/oauth/v1/health_check";
        private string ClientId { get; }
        private string ClientSecret { get; }
        private string ApiHost { get; }
        private readonly HttpClient httpClient;

        public Client(string clientId, string clientSecret, string apiHost) : this(clientId, clientSecret, apiHost, new HttpClientHandler())
        {
        }

        public Client(string clientId, string clientSecret, string apiHost, HttpMessageHandler httpMessageHandler) // TODO replace with Builder pattern later
        {
            this.ClientId = clientId; // TODO validations on these
            this.ClientSecret = clientSecret;
            this.ApiHost = apiHost;
            httpClient = new HttpClient(httpMessageHandler);
        }

        /// <summary>
        /// Call the Duo health check endpoint to determine if Duo is healthy (able to service requests)
        /// </summary>
        /// <returns>true if Duo is healthy, false otherwise</returns>
        public async Task<bool> DoHealthCheck()
        {
            string healthCheckUrl = string.Format(HEALTH_CHECK_ENDPOINT, this.ApiHost);

            var additionalClaims = new Dictionary<string, string>
            {
                {JwtRegisteredClaimNames.Sub, ClientId}
            };

            string jwt = JwtUtils.CreateSignedJwt(ClientId, ClientSecret, healthCheckUrl, additionalClaims);

            var parameters = new Dictionary<string, string>() {  // TODO de-magic-string this
                {"client_id", ClientId},
                {"client_assertion", jwt}
            };

            try
            {
                var response = await DoPost<HealthCheckResponse>(healthCheckUrl, parameters);
                return response.Stat == "OK";
            }
            catch (HttpRequestException)
            {
                // Interpret HTTP exceptions as Duo being unhealthy
                return false;
            }
        }

        /// <summary>
        /// Do an HTTP POST API call to the specified url with the specified parameters, and return the response, deserialized from JSON.
        /// </summary>
        /// <param name="url">The API endpoint URL</param>
        /// <param name="parameters">The POST parameters to send</param>
        /// <typeparam name="T">The Type to deserialize the response into</typeparam>
        /// <returns>An object of type T representing the API response</returns>
        private async Task<T> DoPost<T>(string url, IDictionary<string, string> parameters)
        {
            HttpContent content = new FormUrlEncodedContent(parameters);
            HttpResponseMessage httpResponse = await httpClient.PostAsync(url, content);

            // This can throw an HttpRequestException
            httpResponse.EnsureSuccessStatusCode();

            return await httpResponse.Content.ReadFromJsonAsync<T>();
        }

        // TODO probably move to a different file to get them out of the way because there'll be more later
        [DataContract]
        private class HealthCheckResponseDetail
        {
            public int Timestamp { get; set; }
            public string Code { get; set; }
            public string Message { get; set; }
            [DataMember(Name = "message_detail")]
            public string MessageDetail { get; set; }
        }

        [DataContract]
        private class HealthCheckResponse
        {
            public string Stat { get; set; }
            public HealthCheckResponseDetail Response { get; set; }
        }

        public static string GenerateState()
        {
            return GenerateState(DEFAULT_STATE_LENGTH);
        }

        public static string GenerateState(int length)
        {
            if (length > MAXIMUM_STATE_LENGTH || length < MINIMUM_STATE_LENGTH)
            {
                throw new ArgumentException("Invalid state length " + length + " requested.");  // TODO indicate what the valid lengths are
            }
    
            return Utils.GenerateRandomString(length);
        }
    }
}
