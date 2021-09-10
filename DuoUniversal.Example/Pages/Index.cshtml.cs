using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace DuoUniversal.Example.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        private readonly IConfiguration _configuration;  // TODO overkill to get the whole config, just encapsulate the Duo config?

        public IndexModel(ILogger<IndexModel> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public void OnGet()
        {

        }

        public async Task<IActionResult> OnPost(string username)
        {
            string clientId = _configuration.GetValue<string>("Client ID");
            string clientSecret = _configuration.GetValue<string>("Client Secret");
            string apiHost = _configuration.GetValue<string>("API Host");
            string redirectUri = _configuration.GetValue<string>("Redirect URI");
            Client duoClient = new Client(clientId, clientSecret, apiHost, redirectUri);

            await duoClient.DoHealthCheck();  // TODO handle exception?

            string state = Client.GenerateState();
            string promptUri = duoClient.GenerateAuthUri(username, state); // TODO handle exception?

            return new RedirectResult(promptUri);
        }
    }
}
