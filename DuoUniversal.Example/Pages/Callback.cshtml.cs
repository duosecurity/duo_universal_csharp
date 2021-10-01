// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause


using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace DuoUniversal.Example.Pages
{
    /// <summary>
    /// This is the page that Duo redirects back to (/duo_callback) because we specified it in the configuration.
    ///  GET expects the Duo response code and completes the Duo authentication.  Upon successful auth, this displays the IdToken.
    /// </summary>
    public class CallbackModel : PageModel
    {
        private readonly IDuoClientProvider _duoClientProvider;

        public string AuthResponse { get; set; }

        public CallbackModel(IDuoClientProvider duoClientProvider)
        {
            _duoClientProvider = duoClientProvider;
        }

        public async Task<IActionResult> OnGet(string state, string code)
        {
            // Duo should have sent a 'state' and 'code' parameter.  If either is missing or blank, something is wrong.
            if (string.IsNullOrWhiteSpace(state))
            {
                throw new DuoException("Required state value was empty");
            }
            if (string.IsNullOrWhiteSpace(code))
            {
                throw new DuoException("Required code value was empty");
            }

            // Get the Duo client again.  This can be either be cached in the session or newly built.
            // The only stateful information in the Client is your configuration, so you could even use the same client for multiple
            // user authentications if desired.
            Client duoClient = _duoClientProvider.GetDuoClient();

            // The original state value sent to Duo, as well as the username that started the auth, should be stored in the session.
            var sessionState = HttpContext.Session.GetString(IndexModel.STATE_SESSION_KEY);
            var sessionUsername = HttpContext.Session.GetString(IndexModel.USERNAME_SESSION_KEY);
            // If either is missing, something is wrong.
            if (string.IsNullOrEmpty(sessionState) || string.IsNullOrEmpty(sessionUsername))
            {
                throw new DuoException("State or username were missing from your session");
            }

            // Confirm the original state (from the session) matches the state sent by Duo; this helps prevents replay attacks or session takeover
            if (!sessionState.Equals(state))
            {
                throw new DuoException("Session state did not match the expected state");
            }

            HttpContext.Session.Clear();

            // Get a summary of the authentication from Duo.  This will trigger an exception if the username does not match.
            IdToken token = await duoClient.ExchangeAuthorizationCodeFor2faResult(code, sessionUsername);

            // Do whatever checks you want on the returned information.  For this example, we'll simply print it to an HTML page.
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            AuthResponse = JsonSerializer.Serialize(token, options);
            return Page();
        }
    }
}

