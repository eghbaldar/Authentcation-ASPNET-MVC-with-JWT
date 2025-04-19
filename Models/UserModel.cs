namespace JWT.Models
{
    // Models/UserModel.cs
    public class UserModel
    {
        public Guid UserId { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }

}
