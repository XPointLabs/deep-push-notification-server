using System.Text;
using System.Text.Json;
using Deep.Push.Server.Data;
using Deep.Push.Server.Models;
using Deep.Push.Server.Security;
using Deep.Push.Server.Services;
using Microsoft.EntityFrameworkCore;
using Sodium;

namespace Deep.Push.Server.Tests;

public sealed class PushProtocolTests
{
    [Fact]
    public void SubscriptionSignature_BindsSessionIdAndPayload()
    {
        var identity = TestIdentity.Create();
        const long timestamp = 1_800_000_000;
        var message = $"MONITOR{identity.SessionId}{timestamp}10";
        var signature = Convert.ToHexStringLower(PublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(message), identity.PrivateKey));

        Assert.True(SubscriptionSignatureVerifier.VerifySubscribe(identity.SessionId, identity.PublicKeyHex, timestamp, true, [0], signature));
        Assert.False(SubscriptionSignatureVerifier.VerifySubscribe(identity.SessionId, identity.PublicKeyHex, timestamp, false, [0], signature));
    }

    [Fact]
    public async Task SubscriptionAndNotification_AreIdempotentAndNamespaceAware()
    {
        await using var db = CreateDatabase();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var identity = TestIdentity.Create();
        var request = identity.SubscribeRequest(now.ToUnixTimeSeconds(), [0, 5]);
        var service = new SubscriptionService(db, new FixedTimeProvider(now));

        var first = Assert.IsType<OperationResponse>(await service.SubscribeAsync(JsonSerializer.SerializeToElement(request), default));
        var second = Assert.IsType<OperationResponse>(await service.SubscribeAsync(JsonSerializer.SerializeToElement(request), default));
        Assert.True(first.Success);
        Assert.True(first.Added);
        Assert.False(second.Added);

        Assert.Equal(0, await service.QueueNotificationAsync(new(identity.SessionId, "ignored", 3, 1, 2, "hello"), default));
        var notification = new NotifyRequest(identity.SessionId, "message-hash", 5, 1, 2, Convert.ToBase64String("hello"u8));
        Assert.Equal(1, await service.QueueNotificationAsync(notification, default));
        Assert.Equal(0, await service.QueueNotificationAsync(notification, default));
        Assert.Single(await db.Deliveries.ToListAsync());

        var renewed = Assert.IsType<OperationResponse>(await service.SubscribeAsync(JsonSerializer.SerializeToElement(request), default));
        Assert.True(renewed.Success);
        Assert.False(renewed.Added);
        Assert.True((await db.Subscriptions.SingleAsync()).ExpiresAt > now);
    }

    [Fact]
    public void NotificationPayload_IsEncryptedSessionCompatibleBencode()
    {
        var key = SodiumCore.GetRandomBytes(32);
        var subscription = new PushSubscription
        {
            Id = Guid.NewGuid(), IdentityKey = "key", Pubkey = "05" + new string('1', 64), SessionEd25519 = new string('2', 64),
            NamespacesJson = "[0]", WantData = true, Service = "firebase", DeviceToken = "device", EncryptionKey = Convert.ToHexStringLower(key)
        };
        var delivery = new PushDelivery
        {
            Id = Guid.NewGuid(), SubscriptionId = subscription.Id, Subscription = subscription, MessageHash = "hash", Namespace = 0,
            MessageTimestamp = 1000, Expiration = 2000, MessageData = Convert.ToBase64String("hello"u8), Status = DeliveryStatus.Pending
        };

        var payload = new NotificationPayloadEncoder().Encode(subscription, delivery);
        var bytes = Convert.FromBase64String(payload["enc_payload"]);
        var plaintext = SecretAeadXChaCha20Poly1305.Decrypt(bytes[24..], bytes[..24], key, []);

        Assert.Equal("1", payload["spns"]);
        Assert.Equal(0, plaintext.Length % 256);
        Assert.StartsWith("l", Encoding.UTF8.GetString(plaintext));
        Assert.Contains("hello", Encoding.UTF8.GetString(plaintext));
    }

    private static PushDbContext CreateDatabase()
    {
        var options = new DbContextOptionsBuilder<PushDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PushDbContext(options);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed record TestIdentity(string SessionId, string PublicKeyHex, byte[] PrivateKey)
    {
        public static TestIdentity Create()
        {
            var pair = PublicKeyAuth.GenerateKeyPair();
            var x25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(pair.PublicKey);
            return new("05" + Convert.ToHexStringLower(x25519), Convert.ToHexStringLower(pair.PublicKey), pair.PrivateKey);
        }

        public SubscribeRequest SubscribeRequest(long timestamp, int[] namespaces)
        {
            var message = $"MONITOR{SessionId}{timestamp}1{string.Join(',', namespaces)}";
            return new(
                SessionId, PublicKeyHex, namespaces, true, "firebase", timestamp,
                Convert.ToHexStringLower(PublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(message), PrivateKey)),
                new ServiceInfo("firebase-device-token"), Convert.ToHexStringLower(SodiumCore.GetRandomBytes(32)));
        }
    }
}
