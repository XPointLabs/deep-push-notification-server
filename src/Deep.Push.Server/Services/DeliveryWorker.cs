using Deep.Push.Server.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Deep.Push.Server.Services;

public sealed class DeliveryWorker(
    IServiceScopeFactory scopeFactory,
    IPushProvider provider,
    NotificationPayloadEncoder encoder,
    IOptions<PushOptions> options,
    TimeProvider timeProvider,
    ILogger<DeliveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await DeliverBatchAsync(stoppingToken); }
            catch (Exception exception) { logger.LogError(exception, "Push delivery batch failed"); }
            await Task.Delay(options.Value.WorkerIntervalMilliseconds, stoppingToken);
        }
    }

    private async Task DeliverBatchAsync(CancellationToken cancellationToken)
    {
        if (!provider.IsReady) return;
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PushDbContext>();
        var now = timeProvider.GetUtcNow();
        var deliveries = await db.Deliveries
            .Include(x => x.Subscription)
            .Where(x => (x.Status == DeliveryStatus.Pending || x.Status == DeliveryStatus.Retry) && x.NextAttemptAt <= now)
            .OrderBy(x => x.CreatedAt)
            .Take(options.Value.BatchSize)
            .ToListAsync(cancellationToken);

        foreach (var delivery in deliveries)
        {
            delivery.Status = DeliveryStatus.Sending;
            delivery.Attempts++;
            await db.SaveChangesAsync(cancellationToken);

            var result = await provider.SendAsync(delivery.Subscription, encoder.Encode(delivery.Subscription, delivery), cancellationToken);
            if (result.Success)
            {
                delivery.Status = DeliveryStatus.Delivered;
                delivery.DeliveredAt = now;
                delivery.ProviderMessageId = result.MessageId;
                delivery.LastError = null;
            }
            else if (result.PermanentFailure || delivery.Attempts >= options.Value.MaxAttempts)
            {
                delivery.Status = DeliveryStatus.Failed;
                delivery.LastError = result.Error;
                if (result.PermanentFailure)
                {
                    delivery.Subscription.ExpiresAt = now;
                }
                logger.LogWarning(
                    "Push delivery {DeliveryId} failed after {Attempts} attempts: {ProviderError}",
                    delivery.Id,
                    delivery.Attempts,
                    result.Error);
            }
            else
            {
                delivery.Status = DeliveryStatus.Retry;
                delivery.LastError = result.Error;
                delivery.NextAttemptAt = now.AddSeconds(Math.Min(300, Math.Pow(2, delivery.Attempts)));
            }

            await db.SaveChangesAsync(cancellationToken);
        }
    }
}
