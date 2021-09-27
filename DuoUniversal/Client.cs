﻿// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DuoUniversal
{
    public class Client
    {
        public const string DUO_UNIVERSAL_CSHARP = "duo_universal_csharp";

        internal const int MINIMUM_STATE_LENGTH = 22;
        internal const int DEFAULT_STATE_LENGTH = 36;
        internal const int MAXIMUM_STATE_LENGTH = 1024;

        private const string HEALTH_CHECK_ENDPOINT = "https://{0}/oauth/v1/health_check";
        private const string AUTH_ENDPOINT = "https://{0}/oauth/v1/authorize";
        private const string TOKEN_ENDPOINT = "https://{0}/oauth/v1/token";

        internal string ClientId { get; set; }
        internal string ClientSecret { get; set; }
        internal string ApiHost { get; set; }
        internal string RedirectUri { get; set; }
        internal HttpClient HttpClient { get; set; }

        internal bool UseDuoCodeAttribute { get; set; } = false;

        internal Client()
        {
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
            };  // TODO would it hurt to send the subject claim?  if not, I could get rid of GenerateSubjectJwt...

            if (UseDuoCodeAttribute)
            {
                additionalClaims[Labels.USE_DUO_CODE_ATTRIBUTE] = "true";
            }

            return JwtUtils.CreateSignedJwt(ClientId, ClientSecret, authEndpoint, additionalClaims);
        }

        /// <summary>
        /// TODO Document
        /// </summary>
        /// <param name="audience"></param>
        /// <returns></returns>
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
            HttpResponseMessage httpResponse = await HttpClient.PostAsync(url, content);

            // This will throw an HttpRequestException if the result code is not in the 200s
            httpResponse.EnsureSuccessStatusCode();

            return await httpResponse.Content.ReadFromJsonAsync<T>();
        }


        /// <summary>
        /// TODO document 
        /// </summary>
        /// <returns></returns>
        public static string GenerateState()
        {
            return GenerateState(DEFAULT_STATE_LENGTH);
        }

        /// <summary>
        ///  TODO document
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string GenerateState(int length)
        {
            if (length > MAXIMUM_STATE_LENGTH || length < MINIMUM_STATE_LENGTH)
            {
                throw new DuoException($"Invalid state length {length} requested.  State must be between {MINIMUM_STATE_LENGTH} and {MAXIMUM_STATE_LENGTH}");
            }

            return Utils.GenerateRandomString(length);
        }
    }

    public class ClientBuilder
    {

        // Required parameters
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _apiHost;
        private readonly string _redirectUri;

        // Optional settings with default values
        private bool _useDuoCodeAttribute = false;
        private bool _sslCertValidation = true;
        private X509Certificate2Collection _customRoots = null;


        // For testing only
        private HttpMessageHandler _httpMessageHandler;

        public ClientBuilder(string clientId, string clientSecret, string apiHost, string redirectUri)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _apiHost = apiHost;
            _redirectUri = redirectUri;
        }

        internal ClientBuilder CustomHandler(HttpMessageHandler httpMessageHandler)
        {
            _httpMessageHandler = httpMessageHandler;

            return this;
        }

        ///  <summary>
        /// Disables SSL certificate validation for the API calls the client makes.
        /// Incomptible with UseCustomRootCertificates since certificates will not be checked.
        /// 
        /// THIS SHOULD NEVER BE USED IN A PRODUCTION ENVIRONMENT
        /// </summary>
        /// <returns>The ClientBuilder</returns>
        public ClientBuilder DisableSslCertificateValidation()
        {
            _sslCertValidation = false;

            return this;
        }

        /// <summary>
        /// Override the set of Duo root certificates used for certificate pinning.  Provide a collection of acceptable root certificates.
        /// 
        /// Incomptible with DisableSslCertificateValidation - if that is enabled, certificate pinning is not done at all. 
        /// </summary>
        /// <param name="customRoots">The custom set of root certificates to trust</param>
        /// <returns>The ClientBuilder</returns>
        public ClientBuilder UseCustomRootCertificates(X509Certificate2Collection customRoots)
        {
            _customRoots = customRoots;

            return this;
        }

        public ClientBuilder UseDuoCodeAttribute()
        {
            _useDuoCodeAttribute = true;

            return this;
        }

        public Client Build()
        {
            Utils.ValidateRequiredParameters(_clientId, _clientSecret, _apiHost, _redirectUri);

            Client duoClient = new Client
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                ApiHost = _apiHost,
                RedirectUri = _redirectUri,
                UseDuoCodeAttribute = _useDuoCodeAttribute
            };

            var httpClient = BuildHttpClient();
            AddUserAgent(httpClient);

            duoClient.HttpClient = httpClient;

            return duoClient;
        }

        /// <summary>
        /// Get the appropriate HttpClient based on the builder settings
        /// </summary>
        /// <returns>An HttpClient according to the builder settings</returns>
        private HttpClient BuildHttpClient()
        {
            var handler = GetMessageHandler();
            return new HttpClient(handler);
        }

        /// <summary>
        /// Get the appropriate HttpMessageHandler based on the builder settings:
        ///   If a custom handler was specified, return that one (TESTS ONLY)
        ///   Otherwise, return a Handler with the appropriate settings
        /// </summary>
        /// <returns>An HttpMessageHandler for use in a client</returns>
        private HttpMessageHandler GetMessageHandler()
        {
            // Custom handler takes precedence
            if (_httpMessageHandler != null)
            {
                return _httpMessageHandler;
            }

            var certPinner = GetCertificatePinner();
            return new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = certPinner
            };
        }

        /// <summary>
        /// Get the appropriate SSL certificate pinner based on the builder settings:
        ///   If certificate validation is disabled, get a pinner that disables validations
        ///   If a custom root cert collection was provided, pin to those
        ///   Otherwise, pin to the Duo certificates
        /// </summary>
        /// <returns>A certificate pinner function</returns>
        private Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetCertificatePinner()
        {
            if (!_sslCertValidation)
            {
                return CertificatePinnerFactory.GetCertificateDisabler();
            }

            if (_customRoots != null)
            {
                return new CertificatePinnerFactory(_customRoots).GetPinner();
            }

            return CertificatePinnerFactory.GetDuoCertificatePinner();
        }

        /// <summary>
        /// Add a user agent to the provided HttpClient.  The user agent will include the version of this client and
        /// information about the OS name
        /// </summary>
        /// <param name="httpClient">The HttpClient to set the user agent on</param>
        private static void AddUserAgent(HttpClient httpClient)
        {
            // Product name and version
            var version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            ProductInfoHeaderValue ua = new ProductInfoHeaderValue(Client.DUO_UNIVERSAL_CSHARP, version);
            httpClient.DefaultRequestHeaders.UserAgent.Add(ua);

            // Additional info
            var os = Environment.OSVersion.ToString();
            ProductInfoHeaderValue stuff = new ProductInfoHeaderValue($"({os})");
            httpClient.DefaultRequestHeaders.UserAgent.Add(stuff);
        }
    }
}
