// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using DuoUniversal.Example.Data;

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
        private readonly AppDbContext _context;

        // Indicator of Duo health
        public bool IsDuoHealthy { get; private set; } = true;
        public bool UsedFallbackAuth { get; private set; } = false;


        public IndexModel(IDuoClientProvider duoClientProvider, AppDbContext context)
        {
            _duoClientProvider = duoClientProvider;
            _context = context;
        }

        public void OnGet()
        {
             // éventuellement : on pourrait faire un health check ici aussi en async,
        // mais pour rester simple on ne le fait qu'au POST (tentative de login).
        }

        public async Task<IActionResult> OnPost(string username, string password)
        {
            // Internal Authentication Step (First Factor)
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                 ModelState.AddModelError(string.Empty, "Username and password are required.");
                 return Page();
            }

            // Verify user against database
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

            if (user == null || user.Password != password)
            {
                // Invalid credentials
                ModelState.AddModelError(string.Empty, "Invalid username or password.");
                return Page();
            }

            // Initiate the Duo authentication for a specific username

            // Get a Duo client
            Client duoClient = _duoClientProvider.GetDuoClient();

            // Check if Duo seems to be healthy and able to service authentications.
            // If Duo were unhealthy, you could possibly send user to an error page, or implement a fail mode
            var isDuoHealthy = await duoClient.DoHealthCheck();

            if (!IsDuoHealthy)
            {
                // >>> Bascule sur Auth traditionnelle uniquement <<<
                // Ici tu mets ta logique “vraie” d’authentification : création du ClaimsPrincipal,
                // cookie d’auth, redirection vers ton appli, etc.
                //
                // Exemple minimaliste avec cookie auth (à adapter selon ton projet) :
                /*
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username)
                };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                */

                UsedFallbackAuth = true;
                ModelState.AddModelError(string.Empty, "Duo est actuellement indisponible. Connexion réalisée sans 2FA.");
                return Page(); // ou RedirectToPage("…") vers ton espace appli
            }

                    // Duo est OK : on continue le flux normal

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
