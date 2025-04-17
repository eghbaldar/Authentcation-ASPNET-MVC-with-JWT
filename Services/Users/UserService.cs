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
        public string UserValid(string email, string password)
        {
            var user = _context.Users.FirstOrDefault(x => x.Email == email && x.Password == password);
            if (user != null)
                return user.Role;
            else
                return null;
        }
        public JWT.Repository.Entities.Users FindUserByEmail(string email)
        {
            return _context.Users.FirstOrDefault(x => x.Email == email);
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
