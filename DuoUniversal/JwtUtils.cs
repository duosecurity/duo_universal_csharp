using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace DuoUniversal
{

    internal class JwtUtils
    {

        private const int FIVE_MINUTES = 5;

        /// <summary>
        /// Generate an OIDC-compliant JWT for the specified client id and audience, signed with the specified secret.
        /// The "iss", "aud", "jti", "iat", "nbf", and "exp" claims will be automatically added.
        /// Additional claims to be included can be specified in the additionalClaims argument
        /// </summary>
        /// <param name="clientId">OIDC Client Id</param>
        /// <param name="clientSecret">OIDC Client secret, used for signing the token</param>
        /// <param name="audience">OIDC Audience</param>
        /// <param name="additionalClaims">Any additional claims to include in the JWT payload</param>
        /// <returns>A signed JWT</returns>
        internal static string CreateSignedJwt(string clientId, string clientSecret, string audience, IDictionary<string, string> additionalClaims)
        {
            ValidateArguments(clientId, clientSecret, audience);

            string payload = GeneratePayload(clientId, audience, additionalClaims);

            return CreateJwtFromPayload(payload, clientSecret);
        }

        /// <summary>
        /// Generate a signed JWT from the given JSON payload, using the provided secret 
        /// </summary>
        /// <param name="payload">The JSON payload to be the body of the JWT</param>
        /// <param name="clientSecret">The shared secret, must be at least 16 characters or an exception will occur</param>
        /// <returns>The signed JWT with the given payload</returns>
        internal static string CreateJwtFromPayload(string payload, string clientSecret)
        {
            return SignPayload(payload, clientSecret);
        }

        internal static void ValidateJwt(string jwt, string subject, string secret, string issuer)
        {
            // TODO T129712 write this
            // TODO and tests
        }

        /// <summary>
        /// Validates the arguments and throws an exception for any that are empty strings
        /// </summary>
        /// <param name="clientId">OIDC Client Id</param>
        /// <param name="clientSecret">OIDC Client secret, used for signing the token</param>
        /// <param name="audience">OIDC Audience</param>
        private static void ValidateArguments(string clientId, string clientSecret, string audience)
        {
            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentException("clientId argument cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(clientSecret))  // TODO There is a minimum length, need to figure out what it is and enforce it
            {
                throw new ArgumentException("clientSecret argument cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(audience))
            {
                throw new ArgumentException("audience argument cannont be empty.");
            }

        }

        /// <summary>
        /// Generate a JSON payload from the provided parameters
        /// </summary>
        /// <param name="clientId">OIDC Client Id</param>
        /// <param name="audience">OIDC Audience</param>
        /// <param name="additionalClaims">Any additional claims to include in the JWT payload</param>
        /// <returns>A JSON string of the provided parameters</returns>
        private static string GeneratePayload(string clientId, string audience, IDictionary<string, string> additionalClaims)
        {
            IDictionary<string, string> payloadParams = GenerateParams(clientId, audience, additionalClaims);

            return SerializeParams(payloadParams);
        }

        /// <summary>
        /// Package the provided parameters into a Dictionary suitable for conversion to a JWT
        /// </summary>
        /// <param name="clientId">OIDC Client Id</param>
        /// <param name="audience">OIDC Audience</param>
        /// <param name="additionalClaims">Any additional claims to include in the JWT payload</param>
        /// <returns>An IDictionary containing the provided parameters keyed by the offical JWT claims identifiers</returns>
        private static IDictionary<string, string> GenerateParams(string clientId, string audience, IDictionary<string, string> additionalClaims)
        {
            string jti = Guid.NewGuid().ToString(); // TODO just generate a random string instead

            var claims = new Dictionary<string, string>() {
                {JwtRegisteredClaimNames.Iss, clientId},
                {JwtRegisteredClaimNames.Aud, audience},
                {JwtRegisteredClaimNames.Jti, jti}
            };

            foreach (KeyValuePair<string, string> claim in additionalClaims)
            {
                // TODO any value in checking for collision?
                claims.Add(claim.Key, claim.Value);
            }

            return claims;
        }

        /// <summary>
        /// Serialize the provided parameter map to JSON
        /// </summary>
        /// <param name="payloadParams">The JWT payload parameters</param>
        /// <returns>A JSON string representation of the provided parameters</returns>
        private static string SerializeParams(IDictionary<string, string> payloadParams)
        {
            return JsonSerializer.Serialize(payloadParams);
        }

        /// <summary>
        /// Create a signed JWT for the provided payload and shared secret
        /// </summary>
        /// <param name="payload">The JSON payload</param>
        /// <param name="secret">The shared secret</param>
        /// <returns></returns>
        private static string SignPayload(string payload, string secret)
        {
            SigningCredentials signingCreds = GenerateSigningCreds(secret);

            JsonWebTokenHandler jwtHandler = new JsonWebTokenHandler
            {
                TokenLifetimeInMinutes = FIVE_MINUTES
            };

            // CreateToken automatically adds "iat","nbf", and "exp" to the payload
            // "exp" is calulcated using the TokenLifetimeInMinutes set above
            return jwtHandler.CreateToken(payload, signingCreds);
        }

        /// <summary>
        /// Generate a signing credential for the given shared secret
        /// </summary>
        /// <param name="secret">The shared secret</param>
        /// <returns>A SigningCredentials to be used by the JWT token creator</returns>
        private static SigningCredentials GenerateSigningCreds(string secret)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(secret);
            SecurityKey signingKey = new SymmetricSecurityKey(keyBytes);
            return new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512);
        }
    }
}
