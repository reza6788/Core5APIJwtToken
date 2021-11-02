using JWTAuthentication.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Data
{
    public class ApiDbContext : IdentityDbContext
    {
        public virtual DbSet<ItemData> Items{ get; set; }
        public virtual DbSet<RefreshToken> RefreshTokens{ get; set; }
     
        public ApiDbContext(DbContextOptions<ApiDbContext> options) :base(options)
        {
        }

    }
}
