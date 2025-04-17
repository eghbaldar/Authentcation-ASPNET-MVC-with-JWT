namespace JWT.Repository.Entities
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public virtual Users User { get; set; }
        public string Token { get; set; }
        public bool Enabled { get; set; }
        public DateTime Expire { get; set; }
        public DateTime InsertDateTime { get; set; }
    }
}
