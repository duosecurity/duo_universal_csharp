using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace DuoUniversal
{
    public class Client
    {
        internal const int MINIMUM_STATE_LENGTH = 22;
        internal const int DEFAULT_STATE_LENGTH = 36;
        internal const int MAXIMUM_STATE_LENGTH = 1024;

        private const string HEALTH_CHECK_ENDPOINT = "https://{0}/oauth/v1/health_check";
        private const string AUTH_ENDPOINT = "https://{0}/oauth/v1/authorize";
        private const string TOKEN_ENDPOINT = "https://{0}/oauth/v1/token";
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

            string jwt = GenerateSubjectJwt(healthCheckUrl);

            var parameters = new Dictionary<string, string>() {
                {Labels.CLIENT_ID, ClientId},
                {Labels.CLIENT_ASSERTION, jwt}
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
        /// Send the authorization code provided by Duo back to Duo in exchange for an Id Token authenticating the user and
        /// providing details about the authentication.
        /// Will raise a DuoException if the username does not match the Id Token.
        /// </summary>
        /// <param name="duoCode">The one-time use code issued by Duo</param>
        /// <param name="username">The username expected to have authenticated with Duo</param>
        /// <returns>An IdToken authenticating the user and describing the authentication</returns>
        public async Task<IdToken> ExchangeAuthorizationCodeFor2faResult(string duoCode, string username)
        {
            string tokenEndpoint = CustomizeApiUri(TOKEN_ENDPOINT);

            string tokenJwt = GenerateSubjectJwt(tokenEndpoint);

            var parameters = new Dictionary<string, string>() {
                {Labels.CODE, duoCode},
                {Labels.CLIENT_ID, ClientId},
                {Labels.CLIENT_ASSERTION, tokenJwt},
                {Labels.CLIENT_ASSERTION_TYPE, Labels.JWT_BEARER_TYPE},
                {Labels.GRANT_TYPE, Labels.AUTHORIZATION_CODE},
                {Labels.REDIRECT_URI, RedirectUri},
            };

            TokenResponse tokenResponse;

            try
            {
                tokenResponse = await DoPost<TokenResponse>(tokenEndpoint, parameters);
            }
            catch (HttpRequestException e)
            {
                throw new DuoException("Error exchanging the code for a 2fa token", e);
            }

            IdToken idToken;
            try
            {
                JwtUtils.ValidateJwt(tokenResponse.IdToken, ClientId, ClientSecret, tokenEndpoint);
                idToken = Utils.DecodeToken(tokenResponse.IdToken);
            }
            catch (Exception e)
            {
                throw new DuoException("Error while parsing the token api response", e);
            }

            if (idToken.Username != username)
            {
                throw new DuoException("The specified username does not match the username from Duo");
            }

            return idToken;
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
            string audience = "https://" + ApiHost; // TODO temporary fix for a Duo-side bug
            var additionalClaims = new Dictionary<string, string>
            {
                {Labels.AUD, audience}, // TODO Temporarily override the audience value until the Duo-side bug is fixed
                {Labels.CLIENT_ID, ClientId},
                {Labels.DUO_UNAME, username},
                {Labels.REDIRECT_URI, RedirectUri},
                {Labels.RESPONSE_TYPE, Labels.CODE},
                {Labels.SCOPE, Labels.OPENID},
                {Labels.STATE, state}
                // TODO support nonce
                // TODO support overriding use_duo_code_attribute
            };  // TODO would it hurt to send the subject claim?  if not, I could get rid of GenerateSubjectJwt...

            return JwtUtils.CreateSignedJwt(ClientId, ClientSecret, authEndpoint, additionalClaims);
        }

        private string GenerateSubjectJwt(string audience)
        {
            // Add the subject claim
            var additionalClaims = new Dictionary<string, string>
            {
                {Labels.SUB, ClientId}
            };

            return JwtUtils.CreateSignedJwt(ClientId, ClientSecret, audience, additionalClaims);
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
            queryStringBuilder.Add(Labels.CLIENT_ID, ClientId);
            queryStringBuilder.Add(Labels.REQUEST, authJwt);
            queryStringBuilder.Add(Labels.RESPONSE_TYPE, Labels.CODE);
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

            // This will throw an HttpRequestException if the result code is not in the 200s
            httpResponse.EnsureSuccessStatusCode();

            return await httpResponse.Content.ReadFromJsonAsync<T>();
        }


        public static string GenerateState()
        {
            return GenerateState(DEFAULT_STATE_LENGTH);
        }

        public static string GenerateState(int length)
        {
            if (length > MAXIMUM_STATE_LENGTH || length < MINIMUM_STATE_LENGTH)
            {
                throw new DuoException($"Invalid state length {length} requested.  State must be between {MINIMUM_STATE_LENGTH} and {MAXIMUM_STATE_LENGTH}");
            }

            return Utils.GenerateRandomString(length);
        }
    }
}
