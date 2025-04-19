using JWT.Models;
using JWT.Repository.Context;
using Microsoft.EntityFrameworkCore;

namespace JWT.Services.Users
{
    public class UserService
    {
        private readonly IDataBaseContext _context;
        public UserService(IDataBaseContext context)
        {
            _context = context;
        }
        public UserModel UserValid(string email, string password)
        {
            var user = _context.Users
                .Select(x => new UserModel
                {
                    Email = x.Email,
                    Password = x.Password,
                    Role = x.Role,
                    UserId = x.Id,
                })
                .FirstOrDefault(x => x.Email == email && x.Password == password);
            if (user != null)
                return user;
            else
                return null;
        }
        public JWT.Repository.Entities.Users FindUserByUserId(Guid userId)
        {
            return _context.Users.FirstOrDefault(x => x.Id == userId);
        }
        public JWT.Repository.Entities.Users FindUserByToken(string token)
        {
            var user = _context.RefreshToken
                .Include(x => x.User)
                .Where(x => x.Token == token)
                .First();
            return user.User;
        }
    }
}
