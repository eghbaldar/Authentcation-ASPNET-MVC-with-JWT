using JWT.Models;
using JWT.Repository.Context;
using JWT.Repository.Entities;
using Microsoft.EntityFrameworkCore;
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
        public bool PostToken(RefreshToken refreshToken)
        {
            // mark revoke all previous tokens
            var tokens = _context.RefreshToken.Where(x => x.UserId == refreshToken.UserId).ToList();
            if (tokens.Any()) foreach (var token in tokens) token.IsRevoked = true;
            // insert
            RefreshToken _refreshToken = new RefreshToken()
            {
                IsRevoked = refreshToken.IsRevoked,
                Expire = refreshToken.Expire,
                Id = Guid.NewGuid(),
                InsertDateTime = DateTime.Now,
                Token = refreshToken.Token,
                UserId = refreshToken.UserId,
            };
            _context.RefreshToken.Add(_refreshToken);
            _context.SaveChanges();
            return true;
        }
        public RefreshToken? IsRefreshTokenValid(string token)
        {
            return _context.RefreshToken
                .Include(x => x.User)
                .Select(x => new RefreshToken
                {
                    Id = x.Id,
                    UserId = x.UserId,
                    Token = x.Token,
                    Expire = x.Expire,
                    InsertDateTime = DateTime.Now,
                    IsRevoked = x.IsRevoked,
                    User = x.User,
                    Role = x.User.Role,
                })
                .Where(x => x.Token == token && !x.IsRevoked && x.Expire >= DateTime.UtcNow)
                .FirstOrDefault();
        }
        public bool DisabledUserTokenByToken(string token)
        {
            _context.RefreshToken.Where(x => x.Token == token).First().IsRevoked = false;
            _context.SaveChanges();
            return true;
        }
    }
}
