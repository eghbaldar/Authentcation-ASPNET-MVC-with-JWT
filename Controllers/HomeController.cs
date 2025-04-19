using System.Diagnostics;
using JWT.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Login()
        {
            return View();
        }
        public IActionResult AccessDenied()
        {
            return View();
        }
        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme, Roles = "Admin")]
        public IActionResult AdminPage()
        {
            return View();
        }
        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme, Roles = "User")]
        public IActionResult UserPage()
        {
            return View();
        }
        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
        public IActionResult AllRoles()
        {
            return View();
        }
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet]
        public IActionResult AllRolesBearer()
        {
            // this page is only accessible directly through TOKEN with ajax in header itself
            // this page is not accessible with simple <a href='/home/AllRolesBearer'></a>
            return Json(new { message = "[Test] => This page is protected by JWT Bearer" });
        }

    }
}
