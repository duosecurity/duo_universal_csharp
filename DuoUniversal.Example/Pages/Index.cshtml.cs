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
            // Save the state and username in the session for later
            HttpContext.Session.SetString(STATE_SESSION_KEY, state);
            HttpContext.Session.SetString(USERNAME_SESSION_KEY, username);

            // Get the URI of the Duo prompt from the client.  This includes an embedded authentication request.
            string promptUri = duoClient.GenerateAuthUri(username, state);

            // Redirect the user's browser to the Duo prompt.
            // The Duo prompt, after authentication, will redirect back to the configured Redirect URI to complete the authentication flow.
            // In this example, that is /duo_callback, which is implemented in Callback.cshtml.cs.
            return new RedirectResult(promptUri);
        }
    }
}
