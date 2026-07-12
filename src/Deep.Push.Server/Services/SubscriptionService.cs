using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Push.Server.Data;
using Deep.Push.Server.Models;
using Deep.Push.Server.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Deep.Push.Server.Services;

public sealed class SubscriptionService(
    PushDbContext db,
    TimeProvider timeProvider,
    IOptions<PushOptions> options)
{
    private static readonly TimeSpan SignatureLifetime = TimeSpan.FromDays(14);
    private static readonly TimeSpan FirebaseSubscriptionLifetime = TimeSpan.FromDays(14);
    private static readonly TimeSpan WnsSubscriptionLifetime = TimeSpan.FromDays(30);
    private static readonly TimeSpan FutureGrace = TimeSpan.FromDays(1);

    public SubscriptionService(PushDbContext db, TimeProvider timeProvider)
        : this(db, timeProvider, Options.Create(new PushOptions()))
    {
    }

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

        if (!TryGetTimestamp(request.SigTs, out var timestamp) || !IsCanonicalSubscribeRequest(request, out var namespaces))
        {
            return Failure("Subscription signature or parameters are invalid.");
        }

        var now = timeProvider.GetUtcNow();
        if (timestamp < now - SignatureLifetime || timestamp > now + FutureGrace ||
            !SubscriptionSignatureVerifier.VerifySubscribe(
                request.SigVersion,
                request.Pubkey,
                request.SessionEd25519,
                request.SigTs,
                request.Data,
                namespaces,
                request.Service,
                request.ServiceInfo.Token,
                request.EncKey,
                request.AppId,
                request.AppVersion,
                request.Signature))
        {
            return Failure("Subscription signature or parameters are invalid.");
        }

        var identity = IdentityKey(request.Pubkey, request.Service, request.ServiceInfo.Token);
        var subscription = await db.Subscriptions.SingleOrDefaultAsync(x => x.IdentityKey == identity, cancellationToken);
        var added = subscription is null;
        subscription ??= new PushSubscription { Id = Guid.NewGuid(), IdentityKey = identity, Pubkey = string.Empty, SessionEd25519 = string.Empty, NamespacesJson = "[]", Service = string.Empty, DeviceToken = string.Empty, EncryptionKey = string.Empty };
        subscription.Pubkey = request.Pubkey;
        subscription.SessionEd25519 = request.SessionEd25519;
        subscription.NamespacesJson = JsonSerializer.Serialize(namespaces);
        subscription.WantData = request.Data;
        subscription.Service = request.Service;
        subscription.DeviceToken = request.ServiceInfo.Token;
        subscription.EncryptionKey = request.EncKey;
        subscription.SignatureTimestamp = request.SigTs;
        subscription.SubscribedAt = now;
        subscription.ExpiresAt = timestamp + GetSubscriptionLifetime(request.Service);
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

        if (!TryGetTimestamp(request.SigTs, out var timestamp) || !IsCanonicalUnsubscribeRequest(request))
        {
            return Failure("Unsubscribe signature or parameters are invalid.");
        }

        var now = timeProvider.GetUtcNow();
        if (Math.Abs((now - timestamp).TotalHours) > 24 ||
            !SubscriptionSignatureVerifier.VerifyUnsubscribe(
                request.SigVersion,
                request.Pubkey,
                request.SessionEd25519,
                request.SigTs,
                request.Service,
                request.ServiceInfo.Token,
                request.Signature))
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
    private bool IsCanonicalSubscribeRequest(SubscribeRequest request, out int[] namespaces)
    {
        namespaces = [];
        if (request.SigVersion != SubscriptionSignatureVerifier.SignatureVersion ||
            request.Namespaces is null || request.Namespaces.Count == 0 ||
            request.ServiceInfo is null || string.IsNullOrWhiteSpace(request.ServiceInfo.Token) ||
            request.ServiceInfo.Token.Length > 4096 ||
            request.ServiceInfo.Token != request.ServiceInfo.Token.Trim() ||
            !IsCanonicalServiceToken(request.Service, request.ServiceInfo.Token) ||
            !string.Equals(request.AppId, PushEnvelopeCrypto.PackageName, StringComparison.Ordinal) ||
            !IsCanonicalAppVersion(request.AppVersion) ||
            !IsLowerHex(request.Pubkey, 66) || !request.Pubkey.StartsWith("05", StringComparison.Ordinal) ||
            !IsLowerHex(request.SessionEd25519, 64) || !IsLowerHex(request.EncKey, 64) ||
            string.IsNullOrWhiteSpace(request.Signature))
        {
            return false;
        }

        namespaces = request.Namespaces.Distinct().Order().ToArray();
        return request.Namespaces.SequenceEqual(namespaces);
    }

    private bool IsCanonicalUnsubscribeRequest(UnsubscribeRequest request) =>
        request.SigVersion == SubscriptionSignatureVerifier.SignatureVersion &&
        request.ServiceInfo is not null && !string.IsNullOrWhiteSpace(request.ServiceInfo.Token) &&
        request.ServiceInfo.Token.Length <= 4096 && request.ServiceInfo.Token == request.ServiceInfo.Token.Trim() &&
        IsCanonicalServiceToken(request.Service, request.ServiceInfo.Token) &&
        IsLowerHex(request.Pubkey, 66) && request.Pubkey.StartsWith("05", StringComparison.Ordinal) &&
        IsLowerHex(request.SessionEd25519, 64) && !string.IsNullOrWhiteSpace(request.Signature);

    private static bool TryGetTimestamp(long value, out DateTimeOffset timestamp)
    {
        try
        {
            timestamp = DateTimeOffset.FromUnixTimeSeconds(value);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            timestamp = default;
            return false;
        }
    }

    private static bool IsLowerHex(string? value, int length) =>
        value is { Length: var actualLength } && actualLength == length &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCanonicalAppVersion(string? value) =>
        value is { Length: > 0 and <= 64 }
        && value == value.Trim()
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or '.' or '-' or '_' or '+');

    private bool IsCanonicalServiceToken(string? service, string token) =>
        service switch
        {
            "firebase" => token.Length is > 0 and <= 4096,
            "wns" => options.Value.WnsEnabled && WnsChannelUriValidator.IsValid(token),
            _ => false
        };

    private static TimeSpan GetSubscriptionLifetime(string service) =>
        string.Equals(service, "wns", StringComparison.Ordinal)
            ? WnsSubscriptionLifetime
            : FirebaseSubscriptionLifetime;

    private static string IdentityKey(string pubkey, string service, string token) =>
        $"{pubkey.ToLowerInvariant()}:{service.ToLowerInvariant()}:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)))}";
}
