using JWT.Repository.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWT.Repository.Context
{
    public interface IDataBaseContext
    {
        public DbSet<Users> Users { get; set; }
        public DbSet<RefreshToken> RefreshToken { get; set; }

        //SaveChanges
        int SaveChanges(bool acceptAllChangesOnSuccess);
        int SaveChanges();
        Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = new CancellationToken());
        Task<int> SaveChangesAsync(CancellationToken cancellationToken = new CancellationToken());
    }
}
