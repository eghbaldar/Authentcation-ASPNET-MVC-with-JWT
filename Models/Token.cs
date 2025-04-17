using JWT.Repository.Entities;

namespace JWT.Models
{
    public class Token
    {
        public string AccessToken { get; set; }
        public RefreshToken RefreshToken { get; set; }
    }
}
