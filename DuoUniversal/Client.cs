using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
        private const string AUTH_ENDPOINT = "https://{0}/oauth/v1/authorize";
        private string ClientId { get; }
        private string ClientSecret { get; }
        private string ApiHost { get; }
        private string RedirectUri { get; }
        private readonly HttpClient httpClient;

        public Client(string clientId, string clientSecret, string apiHost, string redirectUri) : this(clientId, clientSecret, apiHost, redirectUri, new HttpClientHandler())
        {
        }

        public Client(string clientId, string clientSecret, string apiHost, string redirectUri, HttpMessageHandler httpMessageHandler) // TODO replace with Builder pattern later
        {
            this.ClientId = clientId; // TODO validations on these
            this.ClientSecret = clientSecret;
            this.ApiHost = apiHost;
            this.RedirectUri = redirectUri;
            httpClient = new HttpClient(httpMessageHandler);
        }

        /// <summary>
        /// Call the Duo health check endpoint to determine if Duo is healthy (able to service requests)
        /// </summary>
        /// <returns>true if Duo is healthy, false otherwise</returns>
        public async Task<bool> DoHealthCheck()
        {
            string healthCheckUrl = CustomizeApiUri(HEALTH_CHECK_ENDPOINT);

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
        /// Generate the URI to a Duo endpoint that will perform a 2FA authentication for the specified user.
        /// </summary>
        /// <param name="username">The username to authenticate.  Must match a Duo username or alias</param>
        /// <param name="state">A unique identifier for the authentication attempt</param>
        /// <returns>A URL to redirect the user's browser to</returns>
        public string GenerateAuthUri(string username, string state)
        {
            ValidateAuthUriInputs(username, state);

            string authEndpoint = CustomizeApiUri(AUTH_ENDPOINT);

            string authJwt = GenerateAuthJwt(username, state, authEndpoint);

            return BuildAuthUri(authEndpoint, authJwt);
        }

        /// <summary>
        /// Customize a URI template based on the Duo API Host value
        /// </summary>
        /// <param name="baseUrl">The URL template</param>
        /// <returns>The completed URL</returns>
        private string CustomizeApiUri(string baseUrl)
        {
            return string.Format(baseUrl, ApiHost);
        }

        /// <summary>
        /// Ensure the provided username and state inputs are valid:
        ///   Username cannot be blank/whitespace
        ///   State cannot be blank/whitespace, and must be between a minimum and maximum length
        /// </summary>
        /// <param name="username">The username to check</param>
        /// <param name="state">The state value to check</param>
        private void ValidateAuthUriInputs(string username, string state)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new DuoException("username cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(state) || state.Length < MINIMUM_STATE_LENGTH || state.Length > MAXIMUM_STATE_LENGTH)
            {
                throw new DuoException($"state must be a non-empty string between {MINIMUM_STATE_LENGTH} and {MAXIMUM_STATE_LENGTH}.");
            }
        }

        /// <summary>
        /// Generate a JWT authentication request to be sent to Duo
        /// </summary>
        /// <param name="username">The username to authenticate.  Must match a Duo username or alias</param>
        /// <param name="state">A unique identifier for the authentication attempt</param>
        /// <param name="authEndpoint">The Duo endpoint URI</param>
        /// <returns>A signed JWT</returns>
        private string GenerateAuthJwt(string username, string state, string authEndpoint)
        {
            var additionalClaims = new Dictionary<string, string> // TODO de-magic-string these
            {
                {"client_id", ClientId},
                {"duo_uname", username},
                {"redirect_uri", RedirectUri},
                {"response_type", "code"},
                {"scope", "openid"},
                {"state", state}
                // TODO T129715 support nonce
                // TODO T129717 support overriding use_duo_code_attribute
            };

            return JwtUtils.CreateSignedJwt(ClientId, ClientSecret, authEndpoint, additionalClaims);
        }

        /// <summary>
        /// Construct the full URI to the Duo the authentication request endpoint
        /// </summary>
        /// <param name="authEndpoint">The base endpoint URI</param>
        /// <param name="authJwt">An authentication request JWT</param>
        /// <returns>The fully-built URI</returns>
        private string BuildAuthUri(string authEndpoint, string authJwt)
        {
            // NB This handles the URL encoding
            NameValueCollection queryStringBuilder = System.Web.HttpUtility.ParseQueryString(string.Empty);
            queryStringBuilder.Add("client_id", ClientId);  // TODO de-magic-string these
            queryStringBuilder.Add("request", authJwt);
            queryStringBuilder.Add("response_type", "code");
            string queryString = queryStringBuilder.ToString();

            return $"{authEndpoint}?{queryString}";
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
