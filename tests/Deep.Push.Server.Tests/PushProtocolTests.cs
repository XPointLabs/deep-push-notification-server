using System.Text;
using System.Text.Json;
using Deep.Push.Server.Data;
using Deep.Push.Server.Models;
using Deep.Push.Server.Security;
using Deep.Push.Server.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sodium;

namespace Deep.Push.Server.Tests;

public sealed class PushProtocolTests
{
    private const string TestAppVersion = "0.2.8";

    [Fact]
    public void SubscriptionSignature_BindsEveryVersionedSubscribeField()
    {
        var identity = TestIdentity.Create();
        const long timestamp = 1_800_000_000;
        var request = identity.SubscribeRequest(timestamp, [0, 10]);

        Assert.True(VerifySubscribe(request));
        Assert.False(VerifySubscribe(request with { Data = false }));
        Assert.False(VerifySubscribe(request with { Namespaces = [0, 11] }));
        Assert.False(VerifySubscribe(request with { Service = "apns" }));
        Assert.False(VerifySubscribe(request with { ServiceInfo = new ServiceInfo("other-token") }));
        Assert.False(VerifySubscribe(request with { EncKey = new string('b', 64) }));
        Assert.False(VerifySubscribe(request with { AppId = "network.xpoint.other" }));
        Assert.False(VerifySubscribe(request with { AppVersion = "13" }));
        Assert.False(VerifySubscribe(request with { SigTs = timestamp + 1 }));
        Assert.False(VerifySubscribe(request with { SigVersion = 1 }));
    }

    [Fact]
    public void UnsubscribeSignature_BindsProviderAndDeviceToken()
    {
        var identity = TestIdentity.Create();
        const long timestamp = 1_800_000_000;
        var request = identity.UnsubscribeRequest(timestamp);

        Assert.True(SubscriptionSignatureVerifier.VerifyUnsubscribe(
            request.SigVersion,
            request.Pubkey,
            request.SessionEd25519,
            request.SigTs,
            request.Service,
            request.ServiceInfo.Token,
            request.Signature));
        Assert.False(SubscriptionSignatureVerifier.VerifyUnsubscribe(
            request.SigVersion,
            request.Pubkey,
            request.SessionEd25519,
            request.SigTs,
            "apns",
            request.ServiceInfo.Token,
            request.Signature));
        Assert.False(SubscriptionSignatureVerifier.VerifyUnsubscribe(
            request.SigVersion,
            request.Pubkey,
            request.SessionEd25519,
            request.SigTs,
            request.Service,
            "other-token",
            request.Signature));
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
    public async Task SubscriptionService_AcceptsSignedBoundedClientVersions()
    {
        await using var db = CreateDatabase();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var identity = TestIdentity.Create();
        var service = new SubscriptionService(db, new FixedTimeProvider(now));

        var accepted = Assert.IsType<OperationResponse>(await service.SubscribeAsync(
            JsonSerializer.SerializeToElement(identity.SubscribeRequest(now.ToUnixTimeSeconds(), [0], "13")),
            default));
        var rejected = Assert.IsType<OperationResponse>(await service.SubscribeAsync(
            JsonSerializer.SerializeToElement(identity.SubscribeRequest(now.ToUnixTimeSeconds(), [0], "bad version")),
            default));

        Assert.True(accepted.Success);
        Assert.False(rejected.Success);
    }

    [Fact]
    public async Task SubscriptionService_AcceptsOnlySignedCanonicalWnsChannels()
    {
        await using var db = CreateDatabase();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var identity = TestIdentity.Create();
        var service = new SubscriptionService(
            db,
            new FixedTimeProvider(now),
            Options.Create(new PushOptions { WnsEnabled = true }));
        const string channel = "https://wns2-by3p.notify.windows.com/?token=opaque";

        var accepted = Assert.IsType<OperationResponse>(await service.SubscribeAsync(
            JsonSerializer.SerializeToElement(identity.SubscribeRequest(
                now.ToUnixTimeSeconds(),
                [0],
                service: "wns",
                token: channel)),
            default));
        var rejected = Assert.IsType<OperationResponse>(await service.SubscribeAsync(
            JsonSerializer.SerializeToElement(identity.SubscribeRequest(
                now.ToUnixTimeSeconds(),
                [0],
                service: "wns",
                token: "https://notify.windows.com.evil.example/?token=opaque")),
            default));

        Assert.True(accepted.Success);
        Assert.False(rejected.Success);
        var subscription = Assert.Single(await db.Subscriptions.ToListAsync());
        Assert.Equal(now.AddDays(30), subscription.ExpiresAt);
    }

    [Fact]
    public async Task SubscriptionService_RejectsWnsWhileProviderIsDisabled()
    {
        await using var db = CreateDatabase();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var identity = TestIdentity.Create();
        var service = new SubscriptionService(db, new FixedTimeProvider(now));

        var response = Assert.IsType<OperationResponse>(await service.SubscribeAsync(
            JsonSerializer.SerializeToElement(identity.SubscribeRequest(
                now.ToUnixTimeSeconds(),
                [0],
                service: "wns",
                token: "https://wns2-by3p.notify.windows.com/?token=opaque")),
            default));

        Assert.False(response.Success);
        Assert.Empty(await db.Subscriptions.ToListAsync());
    }

    [Fact]
    public async Task SubscriptionService_RejectsTamperingWithoutMutatingState()
    {
        await using var db = CreateDatabase();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var identity = TestIdentity.Create();
        var request = identity.SubscribeRequest(now.ToUnixTimeSeconds(), [0, 10]);
        var service = new SubscriptionService(db, new FixedTimeProvider(now));
        var tampered = new SubscribeRequest[]
        {
            request with { Data = false },
            request with { Namespaces = [0, 11] },
            request with { ServiceInfo = new ServiceInfo("rotated-token") },
            request with { EncKey = new string('b', 64) },
            request with { AppId = "network.xpoint.other" },
            request with { AppVersion = "13" },
            request with { SigTs = now.ToUnixTimeSeconds() + 1 },
            request with { SigVersion = 1 }
        };

        foreach (var candidate in tampered)
        {
            var response = Assert.IsType<OperationResponse>(await service.SubscribeAsync(JsonSerializer.SerializeToElement(candidate), default));
            Assert.False(response.Success);
        }

        Assert.Empty(await db.Subscriptions.ToListAsync());
    }

    [Fact]
    public void NotificationPayload_IsVersionedAesGcmAndContainsNoPlaintext()
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
        var binding = PushEnvelopeCrypto.ComputeSubscriptionBinding(subscription.Pubkey, subscription.Service, subscription.DeviceToken);
        Assert.True(PushEnvelopeCrypto.TryDecrypt(bytes, key, binding, subscription.Pubkey, out var plaintext));

        Assert.Equal("1", payload["spns"]);
        Assert.DoesNotContain("hello", string.Join("", payload.Values));
        Assert.Contains("message_hash", Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public void NotificationPayload_RejectsTamperAndWrongKeyAndFallsBackForOversizeData()
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
            MessageTimestamp = 1000, Expiration = 2000, MessageData = Convert.ToBase64String(new byte[PushEnvelopeCrypto.MaxMessageDataBytes + 1]), Status = DeliveryStatus.Pending
        };

        var metadataOnly = new NotificationPayloadEncoder().Encode(subscription, delivery);
        var metadataEnvelope = Convert.FromBase64String(metadataOnly["enc_payload"]);
        var binding = PushEnvelopeCrypto.ComputeSubscriptionBinding(subscription.Pubkey, subscription.Service, subscription.DeviceToken);
        Assert.True(PushEnvelopeCrypto.TryDecrypt(metadataEnvelope, key, binding, subscription.Pubkey, out var metadataPlaintext));
        var metadataPayload = JsonSerializer.Deserialize<JsonElement>(metadataPlaintext);
        Assert.Equal("hash", metadataPayload.GetProperty("message_hash").GetString());
        Assert.Equal(0, metadataPayload.GetProperty("namespace").GetInt32());
        Assert.Equal(JsonValueKind.Null, metadataPayload.GetProperty("data").ValueKind);

        delivery.MessageData = Convert.ToBase64String("hello"u8);
        var encoded = new NotificationPayloadEncoder().Encode(subscription, delivery);
        var envelope = Convert.FromBase64String(encoded["enc_payload"]);
        envelope[^1] ^= 0x01;
        Assert.False(PushEnvelopeCrypto.TryDecrypt(envelope, key, binding, subscription.Pubkey, out _));
        Assert.False(PushEnvelopeCrypto.TryDecrypt(Convert.FromBase64String(encoded["enc_payload"]), SodiumCore.GetRandomBytes(32), binding, subscription.Pubkey, out _));
        Assert.False(PushEnvelopeCrypto.TryDecrypt(Convert.FromBase64String(encoded["enc_payload"]), key, binding, subscription.SessionEd25519, out _));
        Assert.False(PushEnvelopeCrypto.TryDecrypt("plaintext"u8.ToArray(), key, binding, subscription.Pubkey, out _));
    }

    [Fact]
    public void NotificationPayload_NormalizesStorageMillisecondsToProtocolSeconds()
    {
        var key = SodiumCore.GetRandomBytes(32);
        var subscription = new PushSubscription
        {
            Id = Guid.NewGuid(), IdentityKey = "key", Pubkey = "05" + new string('1', 64), SessionEd25519 = new string('2', 64),
            NamespacesJson = "[0]", WantData = false, Service = "firebase", DeviceToken = "device", EncryptionKey = Convert.ToHexStringLower(key)
        };
        var delivery = new PushDelivery
        {
            Id = Guid.NewGuid(), SubscriptionId = subscription.Id, Subscription = subscription, MessageHash = "hash", Namespace = 0,
            MessageTimestamp = 1_800_000_000_123, Expiration = 1_801_209_600_987, Status = DeliveryStatus.Pending
        };

        var encoded = new NotificationPayloadEncoder().Encode(subscription, delivery);
        var envelope = Convert.FromBase64String(encoded["enc_payload"]);
        var binding = PushEnvelopeCrypto.ComputeSubscriptionBinding(subscription.Pubkey, subscription.Service, subscription.DeviceToken);
        Assert.True(PushEnvelopeCrypto.TryDecrypt(envelope, key, binding, subscription.Pubkey, out var plaintext));

        var payload = JsonSerializer.Deserialize<JsonElement>(plaintext);
        Assert.Equal(1_800_000_000, payload.GetProperty("timestamp").GetInt64());
        Assert.Equal(1_801_209_600, payload.GetProperty("expiration").GetInt64());
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

        public SubscribeRequest SubscribeRequest(
            long timestamp,
            int[] namespaces,
            string appVersion = TestAppVersion,
            string service = "firebase",
            string token = "firebase-device-token")
        {
            var encryptionKey = Convert.ToHexStringLower(SodiumCore.GetRandomBytes(32));
            var message = CreateSubscribeCanonical(
                SessionId,
                timestamp,
                wantData: true,
                namespaces: namespaces,
                service: service,
                deviceToken: token,
                encryptionKey: encryptionKey,
                appId: PushEnvelopeCrypto.PackageName,
                appVersion: appVersion);
            return new(
                SessionId, PublicKeyHex, namespaces, true, service, timestamp,
                Convert.ToHexStringLower(PublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(message), PrivateKey)),
                new ServiceInfo(token), encryptionKey,
                PushEnvelopeCrypto.PackageName, appVersion,
                SubscriptionSignatureVerifier.SignatureVersion);
        }

        public UnsubscribeRequest UnsubscribeRequest(long timestamp)
        {
            const string service = "firebase";
            const string token = "firebase-device-token";
            var message = CreateUnsubscribeCanonical(SessionId, timestamp, service, token);
            return new(
                SessionId,
                PublicKeyHex,
                service,
                timestamp,
                Convert.ToHexStringLower(PublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(message), PrivateKey)),
                new ServiceInfo(token),
                SubscriptionSignatureVerifier.SignatureVersion);
        }
    }

    private static bool VerifySubscribe(SubscribeRequest request) =>
        SubscriptionSignatureVerifier.VerifySubscribe(
            request.SigVersion,
            request.Pubkey,
            request.SessionEd25519,
            request.SigTs,
            request.Data,
            request.Namespaces,
            request.Service,
            request.ServiceInfo.Token,
            request.EncKey,
            request.AppId,
            request.AppVersion,
            request.Signature);

    private static string CreateSubscribeCanonical(
        string pubkey,
        long timestamp,
        bool wantData,
        IReadOnlyList<int> namespaces,
        string service,
        string deviceToken,
        string encryptionKey,
        string appId,
        string appVersion) =>
        CreateCanonical(
            "subscribe",
            ("pubkey", pubkey),
            ("sig_ts", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("service", service),
            ("device_token", deviceToken),
            ("enc_key", encryptionKey),
            ("want_data", wantData ? "1" : "0"),
            ("namespaces", string.Join(',', namespaces.OrderBy(static value => value).Select(static value => value.ToString(System.Globalization.CultureInfo.InvariantCulture)))),
            ("app_id", appId),
            ("app_version", appVersion));

    private static string CreateUnsubscribeCanonical(
        string pubkey,
        long timestamp,
        string service,
        string deviceToken) =>
        CreateCanonical(
            "unsubscribe",
            ("pubkey", pubkey),
            ("sig_ts", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("service", service),
            ("device_token", deviceToken));

    private static string CreateCanonical(string operation, params (string Name, string Value)[] fields)
    {
        var builder = new StringBuilder($"deep.push/{operation}/v{SubscriptionSignatureVerifier.SignatureVersion}\n");
        foreach (var (name, value) in fields)
        {
            builder.Append(name)
                .Append('=')
                .Append(Encoding.UTF8.GetByteCount(value).ToString(System.Globalization.CultureInfo.InvariantCulture))
                .Append(':')
                .Append(value)
                .Append('\n');
        }

        return builder.ToString();
    }
}
