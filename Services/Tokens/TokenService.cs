using JWT.Models;
using JWT.Repository.Context;
using JWT.Repository.Entities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace JWT.Services.Tokens
{
    public class TokenService
    {
        private readonly IDataBaseContext _context;
        private readonly IConfiguration _configuration;
        public TokenService(IDataBaseContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public bool PostToken(RefreshToken refreshToken, Guid userId)
        {
            RefreshToken refreshToken1 = new RefreshToken()
            {
                Enabled = refreshToken.Enabled,
                Expire = refreshToken.Expire,
                Id = Guid.NewGuid(),
                InsertDateTime = DateTime.Now,
                Token = refreshToken.Token,
                UserId = userId
            };
            _context.RefreshToken.Add(refreshToken1);
            _context.SaveChanges();
            return true;
        }
        public bool DisabledUserTokenByUserId(Guid userId)
        {
            _context.RefreshToken.Where(x => x.UserId == userId).First().Enabled = false;
            _context.SaveChanges();
            return true;
        }
        public bool DisabledUserTokenByToken(string token)
        {
            _context.RefreshToken.Where(x => x.Token == token).First().Enabled = false;
            _context.SaveChanges();
            return true;
        }
        public bool IsRefreshTokenValid(string token)
        {
            return _context.RefreshToken.Any(x => x.Token == token && x.Enabled && x.Expire >= DateTime.Now);
        }
        public Token GenerateToken(JWT.Repository.Entities.Users users)
        {
            var accessToken = GenerateAccessToken(users);
            var refreshToken = GenerateRefreshToken();
            return new Token
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            };
        }
        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                Expire = DateTime.Now.AddMonths(1),
                InsertDateTime = DateTime.Now,
                Enabled = true,
            };
            return refreshToken;
        }
        private string GenerateAccessToken(JWT.Repository.Entities.Users users)
        {
            string secretKey = _configuration["JWT:SecretKey"];
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity([
                    new Claim(ClaimTypes.Email ,users.Email ),
                    new Claim(ClaimTypes.Role,users.Role)
                    ]),
                Expires = DateTime.Now.AddMonths(1),
                SigningCredentials = credentials,
                Issuer = _configuration["JWT:Issuer"],
                Audience = _configuration["JWT:Audience"],
            };
            return new JsonWebTokenHandler().CreateToken(tokenDescriptor);
        }
    }
}
