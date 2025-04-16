using System.Diagnostics;
using JWT.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    public class HomeController : Controller
    {
        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
        public IActionResult King()
        {
            return View();
        }
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult SetToken()
        {
            return View();
        }
    }
}
