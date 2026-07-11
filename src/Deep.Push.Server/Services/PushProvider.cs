using Deep.Push.Server.Data;
using FirebaseAdmin.Messaging;

namespace Deep.Push.Server.Services;

public sealed record ProviderResult(bool Success, bool PermanentFailure, string? MessageId = null, string? Error = null);

public interface IPushProvider
{
    bool IsReady { get; }
    Task<ProviderResult> SendAsync(PushSubscription subscription, IReadOnlyDictionary<string, string> payload, CancellationToken cancellationToken);
}

public sealed class FirebasePushProvider(FirebaseAdmin.FirebaseApp app) : IPushProvider
{
    private readonly FirebaseMessaging messaging = FirebaseMessaging.GetMessaging(app);
    public bool IsReady => true;

    public async Task<ProviderResult> SendAsync(PushSubscription subscription, IReadOnlyDictionary<string, string> payload, CancellationToken cancellationToken)
    {
        if (!string.Equals(subscription.Service, "firebase", StringComparison.Ordinal))
        {
            return new(false, true, Error: $"Unsupported provider: {subscription.Service}");
        }

        if (payload.Count != 2 || !payload.TryGetValue("enc_payload", out var encryptedPayload) ||
            !payload.TryGetValue("spns", out var version) || version != PushEnvelopeCrypto.EnvelopeVersion.ToString() ||
            string.IsNullOrWhiteSpace(encryptedPayload) || encryptedPayload.Length > 8192)
        {
            return new(false, true, Error: "Invalid encrypted push payload");
        }

        try
        {
            var messageId = await messaging.SendAsync(new Message
            {
                Token = subscription.DeviceToken,
                Data = payload,
                Android = new AndroidConfig { Priority = Priority.High, TimeToLive = TimeSpan.FromDays(28) }
            }, cancellationToken);
            return new(true, false, messageId);
        }
        catch (FirebaseMessagingException exception)
        {
            var permanent = exception.MessagingErrorCode is MessagingErrorCode.Unregistered or MessagingErrorCode.InvalidArgument or MessagingErrorCode.SenderIdMismatch;
            return new(false, permanent, Error: exception.MessagingErrorCode?.ToString() ?? exception.Message);
        }
    }
}

public sealed class DisabledPushProvider : IPushProvider
{
    public bool IsReady => false;
    public Task<ProviderResult> SendAsync(PushSubscription subscription, IReadOnlyDictionary<string, string> payload, CancellationToken cancellationToken) =>
        Task.FromResult(new ProviderResult(false, false, Error: "Push provider is not configured"));
}
