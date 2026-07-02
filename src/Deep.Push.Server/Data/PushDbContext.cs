using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Deep.Push.Server.Data;

public sealed class PushDbContext(DbContextOptions<PushDbContext> options) : DbContext(options)
{
    public DbSet<PushSubscription> Subscriptions => Set<PushSubscription>();
    public DbSet<PushDelivery> Deliveries => Set<PushDelivery>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<PushSubscription>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.HasIndex(x => x.IdentityKey).IsUnique();
            entity.HasIndex(x => x.Pubkey);
            entity.Property(x => x.IdentityKey).HasMaxLength(512);
            entity.Property(x => x.Pubkey).HasMaxLength(66);
            entity.Property(x => x.SessionEd25519).HasMaxLength(64);
            entity.Property(x => x.Service).HasMaxLength(32);
            entity.Property(x => x.DeviceToken).HasMaxLength(4096);
            entity.Property(x => x.EncryptionKey).HasMaxLength(64);
        });

        modelBuilder.Entity<PushDelivery>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.HasIndex(x => new { x.SubscriptionId, x.MessageHash }).IsUnique();
            entity.HasIndex(x => new { x.Status, x.NextAttemptAt });
            entity.Property(x => x.MessageHash).HasMaxLength(128);
            entity.Property(x => x.ProviderMessageId).HasMaxLength(512);
            entity.Property(x => x.LastError).HasMaxLength(1024);
            entity.HasOne(x => x.Subscription).WithMany(x => x.Deliveries).HasForeignKey(x => x.SubscriptionId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}

public static class DatabaseConfiguration
{
    public static string BuildConnectionString(IConfiguration configuration)
    {
        var configured = configuration.GetConnectionString("Push");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var passwordFile = configuration["Database:PasswordFile"];
        var password = !string.IsNullOrWhiteSpace(passwordFile) && File.Exists(passwordFile)
            ? File.ReadAllText(passwordFile).Trim()
            : configuration["Database:Password"];

        return new NpgsqlConnectionStringBuilder
        {
            Host = configuration["Database:Host"] ?? "localhost",
            Port = configuration.GetValue("Database:Port", 5432),
            Database = configuration["Database:Name"] ?? "deep_push",
            Username = configuration["Database:Username"] ?? "deep_push",
            Password = password ?? "deep_push",
            Pooling = true,
            MaxPoolSize = configuration.GetValue("Database:MaximumPoolSize", 50)
        }.ConnectionString;
    }

    public static async Task MigrateAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PushDbContext>();
        await db.Database.MigrateAsync();
    }
}
