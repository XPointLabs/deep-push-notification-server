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
        await db.Deliveries
            .Where(x => x.Status == DeliveryStatus.Sending && x.NextAttemptAt <= now)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(x => x.Status, DeliveryStatus.Retry)
                    .SetProperty(x => x.NextAttemptAt, now),
                cancellationToken);

        var deliveries = await db.Deliveries
            .Include(x => x.Subscription)
            .Where(x => (x.Status == DeliveryStatus.Pending || x.Status == DeliveryStatus.Retry) && x.NextAttemptAt <= now)
            .OrderBy(x => x.CreatedAt)
            .Take(options.Value.BatchSize)
            .ToListAsync(cancellationToken);

        foreach (var delivery in deliveries)
        {
            try
            {
                delivery.Status = DeliveryStatus.Sending;
                delivery.Attempts++;
                delivery.NextAttemptAt = now.AddMinutes(5);
                await db.SaveChangesAsync(cancellationToken);

                var payload = encoder.Encode(delivery.Subscription, delivery);
                var result = await provider.SendAsync(delivery.Subscription, payload, cancellationToken);
                ApplyProviderResult(delivery, result, now);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                var permanent = exception is ArgumentException or FormatException;
                ApplyFailure(delivery, exception.GetType().Name, permanent, now);
                logger.LogWarning(
                    exception,
                    "Push delivery {DeliveryId} failed during payload preparation or provider dispatch",
                    delivery.Id);
            }

            await db.SaveChangesAsync(cancellationToken);
        }
    }

    private void ApplyProviderResult(PushDelivery delivery, ProviderResult result, DateTimeOffset now)
    {
        if (result.Success)
        {
            delivery.Status = DeliveryStatus.Delivered;
            delivery.DeliveredAt = now;
            delivery.ProviderMessageId = result.MessageId;
            delivery.LastError = null;
            return;
        }

        ApplyFailure(delivery, result.Error, result.PermanentFailure, now);
    }

    private void ApplyFailure(PushDelivery delivery, string? error, bool permanent, DateTimeOffset now)
    {
        if (permanent || delivery.Attempts >= options.Value.MaxAttempts)
        {
            delivery.Status = DeliveryStatus.Failed;
            delivery.LastError = error;
            if (permanent)
            {
                delivery.Subscription.ExpiresAt = now;
            }

            logger.LogWarning(
                "Push delivery {DeliveryId} failed after {Attempts} attempts: {ProviderError}",
                delivery.Id,
                delivery.Attempts,
                error);
            return;
        }

        delivery.Status = DeliveryStatus.Retry;
        delivery.LastError = error;
        delivery.NextAttemptAt = now.AddSeconds(Math.Min(300, Math.Pow(2, delivery.Attempts)));
    }
}
