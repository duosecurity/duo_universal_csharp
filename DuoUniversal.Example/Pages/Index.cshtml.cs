// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace DuoUniversal.Example.Pages
{
    /// <summary>
    /// This is the default/landing page for the application. 
    ///  GET will serve the login form
    ///  POST will handle the username submit and kick off Duo authentication
    /// </summary>
    public class IndexModel : PageModel
    {

        internal const string STATE_SESSION_KEY = "_State";
        internal const string USERNAME_SESSION_KEY = "_Username";
        internal const string NONCE_SESSION_KEY = "_Nonce";


        private readonly IDuoClientProvider _duoClientProvider;

        public IndexModel(IDuoClientProvider duoClientProvider)
        {
            _duoClientProvider = duoClientProvider;
        }

        public void OnGet()
        {

        }

        public async Task<IActionResult> OnPost(string username)
        {
            // Initiate the Duo authentication for a specific username

            // Get a Duo client
            Client duoClient = _duoClientProvider.GetDuoClient();

            // Check if Duo seems to be healthy and able to service authentications.
            // If Duo were unhealthy, you could possibly send user to an error page, or implement a fail mode
            var isDuoHealthy = await duoClient.DoHealthCheck();

            // Generate a random state value to tie the authentication steps together
            string state = Client.GenerateState();
            // Generate a random nonce, which Duo will echo back in the Id Token.  This is optional; if you
            // don't want one, use the GenerateAuthUri overload that does not take a nonce.
            string nonce = Client.GenerateNonce();
            // Save the state, nonce, and username in the session for later
            HttpContext.Session.SetString(STATE_SESSION_KEY, state);
            HttpContext.Session.SetString(NONCE_SESSION_KEY, nonce);
            HttpContext.Session.SetString(USERNAME_SESSION_KEY, username);

            // Describe the authentication to Duo.  Username and state are required; everything else is
            // optional, and Duo leaves out any behavior you don't ask for.  Each option is documented on
            // the AuthUriOptions property itself, and in Duo's API docs at https://duo.com/docs/oauthapi
            var authOptions = new AuthUriOptions(username, state)
            {
                Nonce = nonce
            };

            /* The remaining options are not set because this example does not need them:

            var authOptions = new AuthUriOptions(username, state)
            {
                Nonce = nonce,

                // The name of the application the user is signing in to.  Duo shows this name in the
                // Duo Push notification, so the user can tell what they are approving, and records it
                // in the authentication log.  Duo also returns it after authentication as
                // idToken.AuthContext.Application.DestinationName.
                DestAppName = "Acme Intranet",

                // A stable identifier for that same application, used by Duo to recognize it across
                // authentications even if its name changes.  This is never shown to the user, and only
                // has to be unique within your Duo account.
                DestAppId = "acme-intranet-prod",

                // The name to show in the "user" field of a Duo Push, when the username your
                // application authenticates with is not one the user would recognize.  For example,
                // show someone their email address rather than an internal account id.  This changes
                // only what is displayed; Duo still authenticates the username above.
                DisplayUsername = "a.smith@acme.com",

                // How recently the user must have completed an interactive Duo authentication, in
                // seconds.  If Duo is remembering this user's device from a previous login that is
                // older than this, it ignores that and prompts them again.  3600 means "they must have
                // authenticated within the last hour".
                MaxAge = 3600,

                // Force an interactive authentication no matter how recently the user last completed
                // one, ignoring any remembered device.  Equivalent to MaxAge = 0.  Use this for an
                // action sensitive enough to reconfirm, such as changing payment details.
                Prompt = AuthPrompt.Login
            };

            */

            // Get the URI of the Duo prompt from the client.  This includes an embedded authentication request.
            string promptUri = duoClient.GenerateAuthUri(authOptions);

            // Redirect the user's browser to the Duo prompt.
            // The Duo prompt, after authentication, will redirect back to the configured Redirect URI to complete the authentication flow.
            // In this example, that is /duo_callback, which is implemented in Callback.cshtml.cs.
            return new RedirectResult(promptUri);
        }
    }
}
