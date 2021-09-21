// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using Microsoft.IdentityModel.JsonWebTokens;

namespace DuoUniversal
{
    internal class Labels
    {
        // Labels for arguments/values sent to the Duo OIDC API endpoints, see https://duo.com/docs/oauthapi
        public const string CODE = "code";
        public const string REDIRECT_URI = "redirect_uri";
        public const string REQUEST = "request";

        // Labels for standard OIDC claims
        public const string AUTHORIZATION_CODE = "authorization_code";
        public const string CLIENT_ASSERTION = "client_assertion";
        public const string CLIENT_ASSERTION_TYPE = "client_assertion_type";
        public const string CLIENT_ID = "client_id";
        public const string GRANT_TYPE = "grant_type";
        public const string JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        public const string OPENID = "openid";
        public const string RESPONSE_TYPE = "response_type";
        public const string SCOPE = "scope";
        public const string STATE = "state";

        // Labels for standard JWT claims
        public const string AUD = JwtRegisteredClaimNames.Aud;
        public const string EXP = JwtRegisteredClaimNames.Exp;
        public const string IAT = JwtRegisteredClaimNames.Iat;
        public const string ISS = JwtRegisteredClaimNames.Iss;
        public const string JTI = JwtRegisteredClaimNames.Jti;
        public const string NBF = JwtRegisteredClaimNames.Nbf;
        public const string SUB = JwtRegisteredClaimNames.Sub;

        // Labels for custom Duo claims
        public const string AUTH_CONTEXT = "auth_context";
        public const string AUTH_RESULT = "auth_result";
        public const string AUTH_TIME = "auth_time";
        public const string DUO_UNAME = "duo_uname";
        public const string PREFERRED_USERNAME = "preferred_username";
        public const string USE_DUO_CODE_ATTRIBUTE = "use_duo_code_attribute";
    }
}
