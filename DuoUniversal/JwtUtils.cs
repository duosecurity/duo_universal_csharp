// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

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

        /// <summary>
        /// Validate the provided JWT against the expected audience and issuer, and that the signature is HMAC512 with the correct secret.
        /// Throws a DuoException if any aspect of validation fails, the JWT is malformed, or if the secret is unusable
        /// </summary>
        /// <param name="jwt">The JWT to validate</param>
        /// <param name="expectedAudience">The expected audience claim</param>
        /// <param name="secret">The shared secret that should have been used to sign the JWT</param>
        /// <param name="expectedIssuer">The expected issuer claim</param>
        internal static void ValidateJwt(string jwt, string expectedAudience, string secret, string expectedIssuer)
        {
            ValidateSecret(secret);
            JsonWebTokenHandler jwtHandler = new JsonWebTokenHandler();

            if (!jwtHandler.CanReadToken(jwt))
            {
                throw new DuoException("The Id Token appears to be malformed");
            }

            TokenValidationParameters validationParameters = GetValidationParameters(secret, expectedAudience, expectedIssuer);
            TokenValidationResult result = jwtHandler.ValidateToken(jwt, validationParameters);

            if (!result.IsValid)
            {
                throw new DuoException("JWT validation failed", result.Exception);
            }
        }

        /// <summary>
        /// Validate the provided client secret.  Secrets must be at least 16 characters to be a valid secret for HMAC SHA 512
        /// </summary>
        /// <param name="secret">The secret to check</param>
        private static void ValidateSecret(string secret)
        {
            if (string.IsNullOrWhiteSpace(secret) || secret.Length < 16)
            {
                throw new DuoException("Secret for validation is too short.  It must be at least 16 characters.");
            }
        }

        /// <summary>
        /// Construct the TokenValidationParameters for validating a JWT
        /// </summary>
        /// <param name="secret">The secret that should have been used to sign the JWT</param>
        /// <param name="audience">The expected audience claim</param>
        /// <param name="issuer">The expected issuer claim</param>
        /// <returns>A TokenValidationParameters for validating a JWT</returns>
        private static TokenValidationParameters GetValidationParameters(string secret, string audience, string issuer)
        {
            // Many validations are done by default:
            //   Signing is required by default
            //   Issuer is validated by default
            //   Audience is validated by default
            //   Expiration is required by default
            //   Lifetime (iat / nbf / exp) is validated by default, with a default 5 minute clock skew
            // We additionally enforce that HMACSHA512 was used
            return new TokenValidationParameters
            {
                ValidAlgorithms = new string[] { SecurityAlgorithms.HmacSha512 },
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = GenerateSecurityKey(secret),
            };
        }

        /// <summary>
        /// Validates the arguments and throws an exception for any that are empty strings
        /// </summary>
        /// <param name="clientId">OIDC Client Id</param>
        /// <param name="clientSecret">OIDC Client secret, used for signing the token</param>
        /// <param name="audience">OIDC Audience</param>
        private static void ValidateArguments(string clientId, string clientSecret, string audience)
        {
            ValidateSecret(clientSecret);

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new DuoException("clientId argument cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(audience))
            {
                throw new DuoException("audience argument cannont be empty.");
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
            string jti = Utils.GenerateRandomString(36);

            var claims = new Dictionary<string, string>() {
                {Labels.ISS, clientId},
                {Labels.AUD, audience},
                {Labels.JTI, jti}
            };

            // Caller can provide additional claims, or overwrite the default ones, if necessary
            foreach (KeyValuePair<string, string> claim in additionalClaims)
            {
                claims[claim.Key] = claim.Value;
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
            SecurityKey signingKey = GenerateSecurityKey(secret);
            return new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512);
        }

        /// <summary>
        /// Generate a SecurityKey for the given shared secret 
        /// </summary>
        /// <param name="secret">The shared secret</param>
        /// <returns>A SecurityKey encoding thae share secret</returns>
        private static SecurityKey GenerateSecurityKey(string secret)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(secret);
            return new SymmetricSecurityKey(keyBytes);
        }
    }
}
