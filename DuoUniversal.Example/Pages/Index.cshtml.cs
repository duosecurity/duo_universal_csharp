using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace DuoUniversal.Example.Pages
{
    public class IndexModel : PageModel
    {

        internal const string STATE_SESSION_KEY = "_State";
        internal const string USERNAME_SESSION_KEY = "_Username";

        private readonly ILogger<IndexModel> _logger;

        private readonly IDuoClientProvider _duoClientProvider;

        public IndexModel(ILogger<IndexModel> logger, IDuoClientProvider duoClientProvider)
        {
            _logger = logger;
            _duoClientProvider = duoClientProvider;
        }

        public void OnGet()
        {

        }

        public async Task<IActionResult> OnPost(string username)
        {
            Client duoClient = _duoClientProvider.GetDuoClient();

            await duoClient.DoHealthCheck();

            string state = Client.GenerateState();
            HttpContext.Session.SetString(STATE_SESSION_KEY, state);
            HttpContext.Session.SetString(USERNAME_SESSION_KEY, username);

            string promptUri = duoClient.GenerateAuthUri(username, state);

            return new RedirectResult(promptUri);
        }
    }
}
