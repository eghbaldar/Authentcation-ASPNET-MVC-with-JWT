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
        UserService userService = new UserService(_context);
        UserModel user = userService.UserValid(model.Email, model.Password);

        if (string.IsNullOrEmpty(user.Role)) return Unauthorized();

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var accessTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
            new Claim(ClaimTypes.Name, user.UserId.ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        }),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes_AccessToken),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var accessToken = tokenHandler.CreateToken(accessTokenDescriptor);
        var accessTokenString = tokenHandler.WriteToken(accessToken);

        var refreshToken = Guid.NewGuid().ToString();
        DateTime refreshTokenDatetime = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes_RefreshToken);

        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false,
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenDatetime
        });

        Response.Cookies.Append("authToken", accessTokenString, new CookieOptions
        {
            HttpOnly = true,
            Secure = false,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes_AccessToken)
        });

        // Save refresh token to DB
        RefreshToken _refreshToken = new RefreshToken()
        {
            UserId = user.UserId,
            Token = refreshToken,
            Expire = refreshTokenDatetime,
            IsRevoked = false
        };
        new TokenService(_context, _configuration).PostToken(_refreshToken);
        return Ok(new { token = accessTokenString });
    }

    [HttpPost]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken)) return Unauthorized("Missing refresh token");

        // Retrieve RefreshToken from DB (verify its validity)
        TokenService tokenService = new TokenService(_context, _configuration);
        var tokenFromDb = tokenService.IsRefreshTokenValid(refreshToken);

        if (tokenFromDb == null)
            return Unauthorized("Invalid or expired refresh token");

        // Mark the old refresh token as revoked (to prevent replay attacks)
        tokenService.DisabledUserTokenByToken(refreshToken);

        // Generate new JWT access token
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var claims = new[]
        {
        new Claim(ClaimTypes.Name, tokenFromDb.UserId.ToString()),
        new Claim(ClaimTypes.Role, tokenFromDb.Role) // Optional: could be fetched from DB
    };

        var accessTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes_AccessToken),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };
        var accessToken = tokenHandler.CreateToken(accessTokenDescriptor);
        var newAccessToken = tokenHandler.WriteToken(accessToken);

        Response.Cookies.Append("authToken", newAccessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = false,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes_AccessToken)
        });

        return Ok(new
        {
            accessToken = newAccessToken,
        });
    }


    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {        
        // mark all user's token revoke
        TokenService tokenService = new TokenService(_context, _configuration);
        var refreshToken = Request.Cookies["refreshToken"];
        if (refreshToken != null) tokenService.DisabledUserTokenByToken(refreshToken);
        // Remove auth token
        Response.Cookies.Delete("authToken");
        // Remove refresh token
        Response.Cookies.Delete("refreshToken");
        // Remove ASP.NET Core cookie (if you're using cookie-based auth too)
        Response.Cookies.Delete("UserAuthCookie"); // or ".AspNetCore.Cookies" if that's the default

        return Redirect("/"); // 🔁 redirect to your homepage or landing page
    }

}

