using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Push.Server.Data;
using Deep.Push.Server.Models;
using Deep.Push.Server.Security;
using Microsoft.EntityFrameworkCore;

namespace Deep.Push.Server.Services;

public sealed class SubscriptionService(PushDbContext db, TimeProvider timeProvider)
{
    private static readonly TimeSpan SignatureLifetime = TimeSpan.FromDays(14);
    private static readonly TimeSpan FutureGrace = TimeSpan.FromDays(1);

    public Task<object> SubscribeAsync(JsonElement payload, CancellationToken cancellationToken) =>
        ProcessAsync(payload, SubscribeOneAsync, cancellationToken);

    public Task<object> UnsubscribeAsync(JsonElement payload, CancellationToken cancellationToken) =>
        ProcessAsync(payload, UnsubscribeOneAsync, cancellationToken);

    public async Task<int> QueueNotificationAsync(NotifyRequest notification, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var subscriptions = await db.Subscriptions
            .Where(x => x.Pubkey == notification.Pubkey.ToLower() && x.ExpiresAt > now)
            .ToListAsync(cancellationToken);
        var queued = 0;
        foreach (var subscription in subscriptions)
        {
            var namespaces = JsonSerializer.Deserialize<int[]>(subscription.NamespacesJson) ?? [];
            if (!namespaces.Contains(notification.Namespace)) continue;

            var exists = await db.Deliveries.AnyAsync(x => x.SubscriptionId == subscription.Id && x.MessageHash == notification.Hash, cancellationToken);
            if (exists) continue;

            db.Deliveries.Add(new PushDelivery
            {
                Id = Guid.NewGuid(),
                SubscriptionId = subscription.Id,
                MessageHash = notification.Hash,
                Namespace = notification.Namespace,
                MessageTimestamp = notification.Timestamp,
                Expiration = notification.Expiration,
                MessageData = subscription.WantData ? notification.Data : null,
                Status = DeliveryStatus.Pending,
                NextAttemptAt = now,
                CreatedAt = now
            });
            queued++;
        }

        await db.SaveChangesAsync(cancellationToken);
        return queued;
    }

    private async Task<OperationResponse> SubscribeOneAsync(JsonElement element, CancellationToken cancellationToken)
    {
        SubscribeRequest? request;
        try { request = element.Deserialize<SubscribeRequest>(PushJson.Options); }
        catch (JsonException) { request = null; }
        if (request is null) return Failure("Invalid subscription request.");

        var now = timeProvider.GetUtcNow();
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(request.SigTs);
        var namespaces = request.Namespaces.Distinct().Order().ToArray();
        if (request.Namespaces.Count == 0 || !request.Namespaces.SequenceEqual(namespaces) ||
            timestamp < now - SignatureLifetime || timestamp > now + FutureGrace ||
            !string.Equals(request.Service, "firebase", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(request.ServiceInfo.Token) || request.ServiceInfo.Token.Length > 4096 ||
            !IsHex(request.EncKey, 64) ||
            !SubscriptionSignatureVerifier.VerifySubscribe(request.Pubkey.ToLower(), request.SessionEd25519, request.SigTs, request.Data, namespaces, request.Signature))
        {
            return Failure("Subscription signature or parameters are invalid.");
        }

        var identity = IdentityKey(request.Pubkey, request.Service, request.ServiceInfo.Token);
        var subscription = await db.Subscriptions.SingleOrDefaultAsync(x => x.IdentityKey == identity, cancellationToken);
        var added = subscription is null;
        subscription ??= new PushSubscription { Id = Guid.NewGuid(), IdentityKey = identity, Pubkey = string.Empty, SessionEd25519 = string.Empty, NamespacesJson = "[]", Service = string.Empty, DeviceToken = string.Empty, EncryptionKey = string.Empty };
        subscription.Pubkey = request.Pubkey.ToLower();
        subscription.SessionEd25519 = request.SessionEd25519.ToLower();
        subscription.NamespacesJson = JsonSerializer.Serialize(namespaces);
        subscription.WantData = request.Data;
        subscription.Service = request.Service.ToLower();
        subscription.DeviceToken = request.ServiceInfo.Token;
        subscription.EncryptionKey = request.EncKey.ToLower();
        subscription.SignatureTimestamp = request.SigTs;
        subscription.SubscribedAt = now;
        subscription.ExpiresAt = timestamp + SignatureLifetime;
        if (added) db.Subscriptions.Add(subscription);
        await db.SaveChangesAsync(cancellationToken);
        return new(true, 0, Added: added);
    }

    private async Task<OperationResponse> UnsubscribeOneAsync(JsonElement element, CancellationToken cancellationToken)
    {
        UnsubscribeRequest? request;
        try { request = element.Deserialize<UnsubscribeRequest>(PushJson.Options); }
        catch (JsonException) { request = null; }
        if (request is null) return Failure("Invalid unsubscribe request.");

        var now = timeProvider.GetUtcNow();
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(request.SigTs);
        if (Math.Abs((now - timestamp).TotalHours) > 24 ||
            !SubscriptionSignatureVerifier.VerifyUnsubscribe(request.Pubkey.ToLower(), request.SessionEd25519, request.SigTs, request.Signature))
        {
            return Failure("Unsubscribe signature or parameters are invalid.");
        }

        var identity = IdentityKey(request.Pubkey, request.Service, request.ServiceInfo.Token);
        var subscription = await db.Subscriptions.SingleOrDefaultAsync(x => x.IdentityKey == identity, cancellationToken);
        if (subscription is not null) db.Subscriptions.Remove(subscription);
        await db.SaveChangesAsync(cancellationToken);
        return new(true, 0, Removed: subscription is not null);
    }

    private static async Task<object> ProcessAsync(JsonElement payload, Func<JsonElement, CancellationToken, Task<OperationResponse>> operation, CancellationToken cancellationToken)
    {
        if (payload.ValueKind == JsonValueKind.Array)
        {
            var results = new List<OperationResponse>();
            foreach (var item in payload.EnumerateArray()) results.Add(await operation(item, cancellationToken));
            return results;
        }
        return await operation(payload, cancellationToken);
    }

    private static OperationResponse Failure(string message) => new(false, 1, message);
    private static bool IsHex(string value, int length) => value.Length == length && value.All(Uri.IsHexDigit);
    private static string IdentityKey(string pubkey, string service, string token) =>
        $"{pubkey.ToLowerInvariant()}:{service.ToLowerInvariant()}:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)))}";
}
