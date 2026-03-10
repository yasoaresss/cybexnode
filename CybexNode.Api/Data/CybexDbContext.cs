using CybexNode.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace CybexNode.Api.Data;

public class CybexDbContext : DbContext
{
    public CybexDbContext(DbContextOptions<CybexDbContext> options) : base(options) { }

    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<User> Users => Set<User>();
    public DbSet<CveEntry> CveEntries => Set<CveEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.ApiKey)
            .IsUnique();

        modelBuilder.Entity<Incident>(entity =>
        {
            entity.Property(i => i.SourceIp).HasMaxLength(45);
            entity.Property(i => i.Protocol).HasMaxLength(20);
            entity.Property(i => i.AttackType).HasMaxLength(100);
            entity.Property(i => i.SensorId).HasMaxLength(100);
            entity.Property(i => i.SessionId).HasMaxLength(100);
            entity.Property(i => i.EventId).HasMaxLength(100);
            entity.Property(i => i.Severity).HasMaxLength(20);
            entity.Property(i => i.DataSource).HasMaxLength(50);
            entity.Property(i => i.SourceCountry).HasMaxLength(10);
        });

        modelBuilder.Entity<Alert>(entity =>
        {
            entity.Property(a => a.Severity).HasMaxLength(20);
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(u => u.Username).HasMaxLength(100);
            entity.Property(u => u.Email).HasMaxLength(200);
            entity.Property(u => u.ApiKey).HasMaxLength(128);
        });

        modelBuilder.Entity<CveEntry>(entity =>
        {
            entity.Property(c => c.CveId).HasMaxLength(30);
            entity.Property(c => c.VendorProject).HasMaxLength(100);
            entity.Property(c => c.Product).HasMaxLength(200);
            entity.Property(c => c.VulnerabilityName).HasMaxLength(300);
            entity.Property(c => c.Severity).HasMaxLength(20);
            entity.HasIndex(c => c.CveId).IsUnique();
        });
    }
}
