namespace JWT.Repository.Entities
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public virtual Users User { get; set; }
        public string? Role { get; set; }
        public string Token { get; set; } // RefreshToken 
        public bool IsRevoked { get; set; } // The IsRevoked field is typically a boolean flag used when storing refresh tokens in a database. Its purpose is to track whether a token has been invalidated (revoked) before its natural expiration time.
        public DateTime Expire { get; set; }
        public DateTime InsertDateTime { get; set; }
    }
}
