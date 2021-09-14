
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace DuoUniversal.Example.Pages
{
    public class CallbackModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        private readonly IDuoClientProvider _duoClientProvider;

        public string AuthResponse { get; set; }

        public CallbackModel(ILogger<IndexModel> logger, IDuoClientProvider duoClientProvider)
        {
            _logger = logger;
            _duoClientProvider = duoClientProvider;
        }

        public async Task<IActionResult> OnGet(string state, string code)
        {
            Client duoClient = _duoClientProvider.GetDuoClient();

            var sessionState = HttpContext.Session.GetString(IndexModel.STATE_SESSION_KEY);
            var sessionUsername = HttpContext.Session.GetString(IndexModel.USERNAME_SESSION_KEY);
            if (string.IsNullOrEmpty(sessionState) || string.IsNullOrEmpty(sessionUsername))
            {
                throw new DuoException("State or username were missing from your session");
            }

            if (!sessionState.Equals(state))
            {
                throw new DuoException("Session state did not match the expected state");
            }

            HttpContext.Session.Clear();

            IdToken token = await duoClient.ExchangeAuthorizationCodeFor2faResult(code, sessionUsername);
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            AuthResponse = JsonSerializer.Serialize(token, options);
            return Page();
        }
    }
}

