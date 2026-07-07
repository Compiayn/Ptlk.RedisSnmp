using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<SnmpCredentialConfig> SnmpCredentialConfigs => Set<SnmpCredentialConfig>();
    public DbSet<SnmpAgentConfig> SnmpAgentConfigs => Set<SnmpAgentConfig>();
    public DbSet<SnmpPointConfig> SnmpPointConfigs => Set<SnmpPointConfig>();
    public DbSet<RedisMapping> RedisMappings => Set<RedisMapping>();
    public DbSet<CommandExecution> CommandExecutions => Set<CommandExecution>();
    public DbSet<SystemLogEntry> SystemLogEntries => Set<SystemLogEntry>();
    public DbSet<SnmpLogEntry> SnmpLogEntries => Set<SnmpLogEntry>();
    public DbSet<MibImportJob> MibImportJobs => Set<MibImportJob>();
    public DbSet<MibNode> MibNodes => Set<MibNode>();
    public DbSet<SnmpTrapLogEntry> SnmpTrapLogEntries => Set<SnmpTrapLogEntry>();
    public DbSet<SnmpTrapRuleConfig> SnmpTrapRuleConfigs => Set<SnmpTrapRuleConfig>();

    public override int SaveChanges()
    {
        TouchUpdatedAt();
        return base.SaveChanges();
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        TouchUpdatedAt();
        return base.SaveChangesAsync(cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<SnmpCredentialConfig>(entity =>
        {
            entity.HasIndex(c => c.Name).IsUnique();
            entity.Property(c => c.Name).HasMaxLength(160).IsRequired();
            entity.Property(c => c.Version).HasMaxLength(16).IsRequired();
            entity.Property(c => c.ProtectedCommunity).HasMaxLength(2000);
            entity.Property(c => c.SecurityName).HasMaxLength(160);
            entity.Property(c => c.SecurityLevel).HasMaxLength(32);
            entity.Property(c => c.AuthProtocol).HasMaxLength(32);
            entity.Property(c => c.ProtectedAuthPassword).HasMaxLength(2000);
            entity.Property(c => c.PrivProtocol).HasMaxLength(32);
            entity.Property(c => c.ProtectedPrivPassword).HasMaxLength(2000);
            entity.Property(c => c.Description).HasMaxLength(1000);
        });

        modelBuilder.Entity<SnmpAgentConfig>(entity =>
        {
            entity.HasIndex(a => a.AgentId).IsUnique();
            entity.HasIndex(a => a.DisplayName).IsUnique();
            entity.Property(a => a.AgentId).HasMaxLength(160).IsRequired();
            entity.Property(a => a.DisplayName).HasMaxLength(160).IsRequired();
            entity.Property(a => a.Host).HasMaxLength(255).IsRequired();
            entity.Property(a => a.SnmpVersion).HasMaxLength(16).IsRequired();
            entity.Property(a => a.Description).HasMaxLength(1000);
            entity.HasOne(a => a.CredentialConfig)
                  .WithMany()
                  .HasForeignKey(a => a.CredentialConfigId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasMany(a => a.Points)
                  .WithOne(p => p.AgentConfig)
                  .HasForeignKey(p => p.AgentConfigId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SnmpPointConfig>(entity =>
        {
            entity.HasIndex(p => new { p.AgentConfigId, p.PointName }).IsUnique();
            entity.HasIndex(p => p.SourcePath).IsUnique();
            entity.Property(p => p.PointName).HasMaxLength(160).IsRequired();
            entity.Property(p => p.SourcePath).HasMaxLength(320).IsRequired();
            entity.Property(p => p.NumericOid).HasMaxLength(160).IsRequired();
            entity.Property(p => p.ValueType).HasMaxLength(32).IsRequired();
            entity.Property(p => p.Access).HasMaxLength(16).IsRequired();
            entity.Property(p => p.Description).HasMaxLength(1000);
            entity.Property(p => p.MibLabel).HasMaxLength(240);
        });

        modelBuilder.Entity<RedisMapping>(entity =>
        {
            entity.HasIndex(m => m.SourcePath).IsUnique();
            entity.HasIndex(m => m.RedisKey).IsUnique();
            entity.Property(m => m.SourcePath).HasMaxLength(320).IsRequired();
            entity.Property(m => m.RedisKey).HasMaxLength(320).IsRequired();
        });

        modelBuilder.Entity<CommandExecution>(entity =>
        {
            entity.HasIndex(c => c.CommandId).IsUnique();
            entity.HasIndex(c => c.RedisKey);
            entity.Property(c => c.CommandId).HasMaxLength(160).IsRequired();
            entity.Property(c => c.Status).HasMaxLength(32).IsRequired();
            entity.Property(c => c.RedisKey).HasMaxLength(320).IsRequired();
            entity.Property(c => c.ErrorCode).HasMaxLength(80);
            entity.Property(c => c.ErrorMessage).HasMaxLength(1000);
        });

        modelBuilder.Entity<SystemLogEntry>(entity =>
        {
            entity.HasIndex(l => l.CreatedAt);
            entity.HasIndex(l => new { l.Category, l.Level });
            entity.HasIndex(l => l.CommandId);
            entity.Property(l => l.Category).HasMaxLength(80).IsRequired();
            entity.Property(l => l.Level).HasMaxLength(32).IsRequired();
            entity.Property(l => l.Message).HasMaxLength(2000).IsRequired();
            entity.Property(l => l.CommandId).HasMaxLength(160);
        });

        modelBuilder.Entity<SnmpLogEntry>(entity =>
        {
            entity.HasIndex(l => l.CreatedAt);
            entity.HasIndex(l => new { l.AgentId, l.NumericOid });
            entity.HasIndex(l => l.CommandId);
            entity.Property(l => l.AgentId).HasMaxLength(160);
            entity.Property(l => l.NumericOid).HasMaxLength(160);
            entity.Property(l => l.Operation).HasMaxLength(80).IsRequired();
            entity.Property(l => l.Level).HasMaxLength(32).IsRequired();
            entity.Property(l => l.Message).HasMaxLength(2000).IsRequired();
            entity.Property(l => l.CommandId).HasMaxLength(160);
            entity.Property(l => l.ErrorCode).HasMaxLength(80);
            entity.HasOne(l => l.AgentConfig)
                  .WithMany()
                  .HasForeignKey(l => l.AgentConfigId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(l => l.PointConfig)
                  .WithMany()
                  .HasForeignKey(l => l.PointConfigId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<MibImportJob>(entity =>
        {
            entity.HasIndex(j => j.ImportId).IsUnique();
            entity.Property(j => j.ImportId).HasMaxLength(64).IsRequired();
            entity.Property(j => j.VersionName).HasMaxLength(160).IsRequired();
            entity.Property(j => j.Status).HasMaxLength(32).IsRequired();
            entity.Property(j => j.SourceFileName).HasMaxLength(255);
            entity.Property(j => j.ErrorMessage).HasMaxLength(2000);
        });

        modelBuilder.Entity<MibNode>(entity =>
        {
            entity.HasIndex(n => new { n.VersionName, n.NumericOid }).IsUnique();
            entity.HasIndex(n => n.SymbolicName);
            entity.Property(n => n.VersionName).HasMaxLength(160).IsRequired();
            entity.Property(n => n.NumericOid).HasMaxLength(160).IsRequired();
            entity.Property(n => n.SymbolicName).HasMaxLength(240);
            entity.Property(n => n.ModuleName).HasMaxLength(160);
            entity.Property(n => n.Syntax).HasMaxLength(80);
            entity.Property(n => n.Access).HasMaxLength(40);
            entity.Property(n => n.Description).HasMaxLength(4000);
        });

        modelBuilder.Entity<SnmpTrapLogEntry>(entity =>
        {
            entity.HasIndex(l => l.ReceivedAt);
            entity.HasIndex(l => new { l.AgentId, l.TrapOid });
            entity.Property(l => l.AgentId).HasMaxLength(160).IsRequired();
            entity.Property(l => l.SourceAddress).HasMaxLength(255).IsRequired();
            entity.Property(l => l.TrapOid).HasMaxLength(160).IsRequired();
            entity.Property(l => l.VarbindsJson).IsRequired();
            entity.Property(l => l.MibLabelsJson).HasMaxLength(4000);
            entity.Property(l => l.RawPayload).HasMaxLength(8000).IsRequired();
        });

        modelBuilder.Entity<SnmpTrapRuleConfig>(entity =>
        {
            entity.HasIndex(r => new { r.AgentId, r.TrapOid }).IsUnique();
            entity.Property(r => r.AgentId).HasMaxLength(160).IsRequired();
            entity.Property(r => r.TrapOid).HasMaxLength(160).IsRequired();
            entity.Property(r => r.DisplayName).HasMaxLength(160).IsRequired();
            entity.Property(r => r.Description).HasMaxLength(1000);
        });
    }

    private void TouchUpdatedAt()
    {
        var now = DateTime.UtcNow;
        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.State == EntityState.Added)
            {
                SetIfPresent(entry.Entity, "CreatedAt", now);
                SetIfPresent(entry.Entity, "UpdatedAt", now);
            }
            else if (entry.State == EntityState.Modified)
            {
                SetIfPresent(entry.Entity, "UpdatedAt", now);
            }
        }
    }

    private static void SetIfPresent(object entity, string propertyName, DateTime value)
    {
        var property = entity.GetType().GetProperty(propertyName);
        if (property?.CanWrite == true && property.PropertyType == typeof(DateTime))
        {
            property.SetValue(entity, value);
        }
    }
}
