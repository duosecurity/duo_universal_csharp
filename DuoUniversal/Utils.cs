using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace DuoUniversal
{
    internal class Utils
    {
        /// <summary>
        /// Generate a cyptographically random alphanumeric string of the specified length
        /// </summary>
        /// <param name="length">The desired length</param>
        /// <returns>A random string of the specified length</returns>
        internal static string GenerateRandomString(int length)
        {
            if (length <= 0)
            {
                throw new DuoException("Cannot generate random strings shorter than 1 character.");
            }

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                StringBuilder sb = new StringBuilder();
                while (sb.Length < length)
                {
                    sb.Append(GenerateValidChar(rng));
                }
                return sb.ToString().Substring(0, length);
            }
        }

        /// <summary>
        /// Randomly generate a valid character from the provided RNG
        /// </summary>
        /// <param name="rng">The RNG to use</param>
        /// <returns>A randomly-selected alphanumeric character</returns>
        private static char GenerateValidChar(RNGCryptoServiceProvider rng)
        {
            byte[] b = new byte[1];
            char c;
            do
            {
                rng.GetBytes(b);
                c = (char)b[0];
            } while (!char.IsLetterOrDigit(c));

            return c;
        }

        /// <summary>
        /// Decode a JWT into an IdToken.  This simply decodes the JWT, but does not validate it.
        /// An exception will be thrown if the JWT is not suitable for decoding into an IdToken
        /// </summary>
        /// <param name="jwt">The jwt to decode</param>
        /// <returns>The IdToken representing the given JWT</returns>
        internal static IdToken DecodeToken(string jwt)
        {
            try
            {
                JsonWebToken token = new JsonWebToken(jwt);

                string authContextJson = token.GetClaim(Labels.AUTH_CONTEXT).Value;
                AuthContext authContext = JsonSerializer.Deserialize<AuthContext>(authContextJson);

                string authResultJson = token.GetClaim(Labels.AUTH_RESULT).Value;
                AuthResult authResult = JsonSerializer.Deserialize<AuthResult>(authResultJson);

                int authTime = int.Parse(token.GetClaim(Labels.AUTH_TIME).Value);
                string username = token.GetClaim(Labels.PREFERRED_USERNAME).Value;
                // Realistically there will only ever be one Audience value
                var audiences = string.Join(",", token.Audiences);

                return new IdToken
                {
                    AuthContext = authContext,
                    AuthResult = authResult,
                    AuthTime = authTime,
                    Username = username,
                    Iss = token.Issuer,
                    Exp = token.ValidTo,
                    Iat = token.IssuedAt,
                    Sub = token.Subject,
                    Aud = audiences
                    // TODO Nonce
                };
            }
            catch (Exception e)
            {
                throw new DuoException("Error while parsing the auth token response", e);
            }
        }

        internal static void ValidateRequiredParameters(string clientId, string clientSecret, string apiHost, string redirectUri)
        {
            // TODO
        }
    }
}
