
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace DuoUniversal.Example.Pages
{
    public class CallbackModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        private readonly IConfiguration _configuration;  // TODO overkill to get the whole config, just encapsulate the Duo config?

        public CallbackModel(ILogger<IndexModel> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async void OnGet(string state, string code)
        {
            string clientId = _configuration.GetValue<string>("Client ID"); // TODO duplicated
            string clientSecret = _configuration.GetValue<string>("Client Secret");
            string apiHost = _configuration.GetValue<string>("API Host");
            string redirectUri = _configuration.GetValue<string>("Redirect URI");
            Client duoClient = new Client(clientId, clientSecret, apiHost, redirectUri);

            // TODO need to match the states, will need session-like store
            // TODO need the username, probably from the session

            IdToken token = await duoClient.ExchangeAuthorizationCodeFor2faResult(code, "username"); // TODO hack for now
            string tokenJson = JsonSerializer.Serialize(token);
            _logger.LogInformation(tokenJson);
        }
    }
}

