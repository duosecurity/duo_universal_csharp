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

            await duoClient.DoHealthCheck();  // TODO handle exception?

            string state = Client.GenerateState();
            // TODO de-magic string these
            HttpContext.Session.SetString("_State", state);
            HttpContext.Session.SetString("_Username", username);

            string promptUri = duoClient.GenerateAuthUri(username, state); // TODO handle exception?

            return new RedirectResult(promptUri);
        }
    }
}
