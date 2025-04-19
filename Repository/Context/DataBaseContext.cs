using JWT.Repository.Entities;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace JWT.Repository.Context
{
    public class DataBaseContext : DbContext, IDataBaseContext
    {
        public DataBaseContext(DbContextOptions options) : base(options)
        {

        }
        public DbSet<Users> Users { get; set; }
        public DbSet<RefreshToken> RefreshToken { get; set; }
        public override int SaveChanges()
        {
            return base.SaveChanges();
        }
    }
}
