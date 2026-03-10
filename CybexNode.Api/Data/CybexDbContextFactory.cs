using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CybexNode.Api.Data;

public class CybexDbContextFactory : IDesignTimeDbContextFactory<CybexDbContext>
{
    public CybexDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<CybexDbContext>();
        optionsBuilder.UseSqlServer(
            "Server=localhost\\SQLEXPRESS;Database=CybexNodeDb;Trusted_Connection=True;TrustServerCertificate=True;"
        );
        return new CybexDbContext(optionsBuilder.Options);
    }
}