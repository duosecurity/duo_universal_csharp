// SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

namespace DuoUniversal
{
    /// <summary>
    /// The values Duo accepts in an authentication request.  Username and state are required; everything
    /// else is optional and is left out of the request entirely unless it is set, because Duo distinguishes
    /// an absent value from one that is present but empty.
    ///
    /// See https://duo.com/docs/oauthapi for what Duo does with each of these.
    /// </summary>
    public class AuthUriOptions
    {
        /// <param name="username">The username to authenticate.  Must match a Duo username or alias</param>
        /// <param name="state">A unique identifier for the authentication attempt</param>
        public AuthUriOptions(string username, string state)
        {
            Username = username;
            State = state;
        }

        /// <summary>
        /// The username to authenticate.  Must match a Duo username or alias.
        /// </summary>
        public string Username { get; }

        /// <summary>
        /// A unique identifier for the authentication attempt.
        /// </summary>
        public string State { get; }

        /// <summary>
        /// A unique value Duo echoes back in the Id Token.  Pass the same value to
        /// ExchangeAuthorizationCodeFor2faResult to have it checked.
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        /// A user-facing name for the application the end user is authenticating to.  Duo shows this in
        /// Duo Mobile, records it in the authentication log, and returns it as
        /// AuthContext.Application.DestinationName.
        /// </summary>
        public string DestAppName { get; set; }

        /// <summary>
        /// A long-lived unique identifier for the application the end user is authenticating to.  Not
        /// shown to the end user.  Must be unique within a Duo customer, but need not be unique across them.
        /// </summary>
        public string DestAppId { get; set; }

        /// <summary>
        /// The username to show in Duo Mobile's "user" field for a Duo Push, in place of the Duo username.
        /// This does not change which user Duo authenticates; that is still Username.
        /// </summary>
        public string DisplayUsername { get; set; }

        /// <summary>
        /// How many seconds may have elapsed since the end user last authenticated interactively.  A
        /// remembered session older than this forces interactive reauthentication.  Zero always forces it,
        /// so this is nullable to keep "no limit requested" distinct from "reauthenticate now".
        /// </summary>
        public int? MaxAge { get; set; }

        /// <summary>
        /// Set to AuthPrompt.Login to force interactive reauthentication even when a remembered session
        /// exists, which is equivalent to a MaxAge of zero.
        /// </summary>
        public AuthPrompt? Prompt { get; set; }
    }

    /// <summary>
    /// The values Duo accepts for the authentication request's prompt behavior.
    /// </summary>
    public enum AuthPrompt
    {
        /// <summary>
        /// Force interactive reauthentication even when a remembered session exists.
        /// </summary>
        Login
    }
}
