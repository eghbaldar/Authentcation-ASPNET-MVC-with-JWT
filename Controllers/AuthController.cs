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
using JWT.Services.Users;
using JWT.Repository.Context;
using JWT.Services.Tokens;
using JWT.Repository.Entities;
using Microsoft.Extensions.Configuration;

public class AuthController : Controller
{
    /// <summary>
    /// //////////////////////////////////////////////////////////////////
    /// In your current code, the refreshTokens dictionary is being used to temporarily map each refresh token to a UserId. 
    /// The dictionary stores this data only for the duration that the application is running. Here's a breakdown:
    /// In production, this dictionary-based store is not persistent. If the server restarts, the tokens are lost.
    /// but...
    /// ⚠️ In A Real-World 
    //////// Store in database.
    //////// Use distributed cache like Redis.
    //////// Add expiration timestamps to refresh tokens.
    /// </summary>


    /// <summary>
    /// the following code is used when you are not going to use DB as storage system 
    ///private static Dictionary<string, string> refreshTokens = new(); // refreshToken -> userId
    /// </summary>

    private readonly JwtSettings _jwtSettings;
    private readonly IDataBaseContext _context;
    private readonly IConfiguration _configuration;
    public AuthController(IOptions<JwtSettings> jwtSettings, IDataBaseContext context, IConfiguration configuration)
    {
        _jwtSettings = jwtSettings.Value;
        _context = context;
        _configuration = configuration;
    }

    [HttpPost]
    public IActionResult Login([FromBody] UserModel model)
    {
        // get validation of user
        // NOTE: or use: Dummy credentials check like: model.Username == "admin" && model.Password == "1234        
        UserService userService = new UserService(_context);
        UserModel user = userService.UserValid(model.Email, model.Password);
        if (string.IsNullOrEmpty(user.Role)) return Unauthorized();

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        // Generate the Access Token (JWT)
        // Set the access token in a cookie (client-side)
        var accessTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, model.UserId.ToString()),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };
        var accessToken = tokenHandler.CreateToken(accessTokenDescriptor);
        var accessTokenString = tokenHandler.WriteToken(accessToken);

        // Generate the Refresh Token (can be a simple GUID or more complex)
        // this code is common between DB and Cookie
        var refreshToken = Guid.NewGuid().ToString();
        // Store refresh token in memory (map to username)
        //refreshTokens[refreshToken] = model.UserId.ToString();

        // Store the refresh token in an HTTP-only cookie (server-side)
        DateTime refreshTokenDatetime = DateTime.UtcNow.AddDays(30);
        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Change to true for production
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenDatetime
        });

        Response.Cookies.Append("authToken", accessTokenString, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Change to true for production
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
        });

        // Replace in-memory dictionary with DB store
        RefreshToken _refreshToken = new RefreshToken()
        {
            UserId = user.UserId,
            Token = refreshToken,
            Expire = refreshTokenDatetime,
            IsRevoked = false
        };
        TokenService tokenService = new TokenService(_context, _configuration);
        tokenService.PostToken(_refreshToken);

        // Create claims for cookie auth
        var claims = new[]
        {
                new Claim(ClaimTypes.Name, model.UserId.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
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

    [HttpPost]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken)) return Unauthorized("Missing refresh token");

        // retrieve RefreshToken from db
        // Plus, Mark the old refresh token as revoked (IsRevoked = true).
        // Insert a new refresh token (a new row in the table).
        // This helps prevent replay attacks (where someone tries to use the same refresh token again), and ensures that each refresh token is single-use, which is a best practice in modern authentication systems.
        TokenService tokenService = new TokenService(_context, _configuration);
        var tokenFromDb = tokenService.IsRefreshTokenValid(refreshToken);    
        if (tokenFromDb == null)
            return Unauthorized("Invalid or expired refresh token");

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, tokenFromDb.UserId.ToString()),
            new Claim(ClaimTypes.Role, tokenFromDb.Role) // Optional: could be fetched from DB
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        //// Generate a new Access Token (JWT)
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

        var newRefreshToken = Guid.NewGuid().ToString();
        DateTime refreshTokenDatetime = DateTime.UtcNow.AddDays(30);
        // Update the access token in a cookie
        Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Change to true for production
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenDatetime
        });
        Response.Cookies.Append("authToken", newAccessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Change to true for production
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
        });
        RefreshToken _refreshToken = new RefreshToken()
        {
            UserId = tokenFromDb.UserId,
            Token = newRefreshToken,
            Expire = refreshTokenDatetime,
            IsRevoked = false
        };
        tokenService.PostToken(_refreshToken);

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

