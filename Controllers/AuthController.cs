// Controllers/AuthController.cs
using JWT.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class AuthController : Controller
{
    private static Dictionary<string, string> refreshTokens = new(); // refreshToken -> username

    private readonly JwtSettings _jwtSettings;

    public AuthController(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    [HttpPost]
    public IActionResult Login([FromBody] UserModel model)
    {
        // Dummy credentials check
        if (model.Username == "admin" && model.Password == "1234")
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

            // Generate the Access Token (JWT)
            var accessTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, model.Username),
                    new Claim(ClaimTypes.Role, "Admin")
                }),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var accessToken = tokenHandler.CreateToken(accessTokenDescriptor);

            // Set the access token in a cookie (client-side)
            var accessTokenString = tokenHandler.WriteToken(accessToken);

            // Generate the Refresh Token (can be a simple GUID or more complex)
            var refreshToken = Guid.NewGuid().ToString();

            // Store the refresh token in an HTTP-only cookie (server-side)
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = false, // Change to true for production
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(30)
            });

            Response.Cookies.Append("authToken", accessTokenString, new CookieOptions
            {
                HttpOnly = true,
                Secure = false, // Change to true for production
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
            });

            // Store refresh token in memory (map to username)
            refreshTokens[refreshToken] = model.Username;


            // Create claims for cookie auth
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
            };

            HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                authProperties
            );

            return Ok(new { token = accessTokenString });
        }

        return Unauthorized();
    }

    [HttpPost]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken) || !refreshTokens.TryGetValue(refreshToken, out var username))
        {
            return Unauthorized("Invalid or missing refresh token");
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var claims = new[]
        {
        new Claim(ClaimTypes.Name, username),
        new Claim(ClaimTypes.Role, "Admin") // Optional: could be fetched from DB
    };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Generate a new Access Token (JWT)
        var accessTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var accessToken = tokenHandler.CreateToken(accessTokenDescriptor);
        var newAccessToken = tokenHandler.WriteToken(accessToken);

        // Update the access token in a cookie
        Response.Cookies.Append("authToken", newAccessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Change to true for production
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
        });

        // Re-sign the user into the cookie authentication scheme
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            authProperties
        );

        return Ok(new { token = newAccessToken });
    }

    // Helper method to extract claims from an expired token (i.e., refresh token)
    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token, byte[] key)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidIssuer = _jwtSettings.Issuer,
            ValidAudience = _jwtSettings.Audience,
            ValidateLifetime = false  // Don't validate the lifetime of the refresh token itself
        };

        var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
        return principal;
    }
    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }
}

