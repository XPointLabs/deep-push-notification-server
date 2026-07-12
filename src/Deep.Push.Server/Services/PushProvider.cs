using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Push.Server.Data;
using FirebaseAdmin.Messaging;
using Microsoft.Extensions.Options;

namespace Deep.Push.Server.Services;

public sealed record ProviderResult(
    bool Success,
    bool PermanentFailure,
    string? MessageId = null,
    string? Error = null,
    bool InvalidateSubscription = false,
    TimeSpan? RetryAfter = null);

public interface IPushProvider
{
    bool IsReady { get; }
    Task<ProviderResult> SendAsync(
        PushSubscription subscription,
        PushDelivery delivery,
        IReadOnlyDictionary<string, string> payload,
        CancellationToken cancellationToken);
}

public interface IPlatformPushProvider : IPushProvider
{
    string Service { get; }
}

public sealed class PushProviderRouter(IEnumerable<IPlatformPushProvider> providers) : IPushProvider
{
    private readonly IReadOnlyDictionary<string, IPlatformPushProvider> providersByService = providers
        .ToDictionary(static provider => provider.Service, StringComparer.Ordinal);

    public bool IsReady => providersByService.Values.Any(static provider => provider.IsReady);

    public Task<ProviderResult> SendAsync(
        PushSubscription subscription,
        PushDelivery delivery,
        IReadOnlyDictionary<string, string> payload,
        CancellationToken cancellationToken) =>
        providersByService.TryGetValue(subscription.Service, out var provider)
            ? provider.SendAsync(subscription, delivery, payload, cancellationToken)
            : Task.FromResult(new ProviderResult(
                false,
                true,
                Error: $"Unsupported provider: {subscription.Service}"));
}

public sealed class FirebasePushProvider(FirebaseAdmin.FirebaseApp app) : IPlatformPushProvider
{
    private readonly FirebaseMessaging messaging = FirebaseMessaging.GetMessaging(app);
    public string Service => "firebase";
    public bool IsReady => true;

    public async Task<ProviderResult> SendAsync(
        PushSubscription subscription,
        PushDelivery delivery,
        IReadOnlyDictionary<string, string> payload,
        CancellationToken cancellationToken)
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
            return new(
                false,
                permanent,
                Error: exception.MessagingErrorCode?.ToString() ?? exception.Message,
                InvalidateSubscription: permanent);
        }
    }
}

public interface IWnsAccessTokenProvider
{
    bool IsConfigured { get; }
    Task<string?> GetTokenAsync(CancellationToken cancellationToken);
    void Invalidate();
}

public sealed class WnsAccessTokenProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<PushOptions> options,
    TimeProvider timeProvider) : IWnsAccessTokenProvider
{
    private static readonly TimeSpan RefreshSkew = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim refreshGate = new(1, 1);
    private readonly object tokenGate = new();
    private string? accessToken;
    private DateTimeOffset expiresAt;

    public bool IsConfigured => options.Value.IsWnsConfigured;

    public async Task<string?> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (!IsConfigured)
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        if (TryGetCachedToken(now, out var cachedToken))
        {
            return cachedToken;
        }

        await refreshGate.WaitAsync(cancellationToken);
        try
        {
            now = timeProvider.GetUtcNow();
            if (TryGetCachedToken(now, out cachedToken))
            {
                return cachedToken;
            }

            var configured = options.Value;
            var clientSecret = ReadClientSecret(configured);
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                $"{Uri.EscapeDataString(configured.WnsTenantId!)}/oauth2/v2.0/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["client_id"] = configured.WnsClientId!,
                    ["client_secret"] = clientSecret,
                    ["scope"] = "https://wns.windows.com/.default"
                })
            };

            using var response = await httpClientFactory
                .CreateClient("WnsOAuth")
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var token = await JsonSerializer.DeserializeAsync<WnsOAuthToken>(stream, cancellationToken: cancellationToken);
            if (token is null || string.IsNullOrWhiteSpace(token.AccessToken) || token.ExpiresIn <= 0)
            {
                return null;
            }

            lock (tokenGate)
            {
                accessToken = token.AccessToken;
                expiresAt = now.AddSeconds(Math.Min(token.ExpiresIn, 86_400));
                return accessToken;
            }
        }
        finally
        {
            refreshGate.Release();
        }
    }

    public void Invalidate()
    {
        lock (tokenGate)
        {
            accessToken = null;
            expiresAt = default;
        }
    }

    private bool TryGetCachedToken(DateTimeOffset now, out string? token)
    {
        lock (tokenGate)
        {
            token = accessToken;
            return !string.IsNullOrWhiteSpace(token) && expiresAt - now > RefreshSkew;
        }
    }

    private static string ReadClientSecret(PushOptions configured)
    {
        if (!string.IsNullOrWhiteSpace(configured.WnsClientSecretFile))
        {
            var file = new FileInfo(configured.WnsClientSecretFile);
            if (!file.Exists || file.Length is <= 0 or > 16_384)
            {
                throw new InvalidOperationException("The configured WNS client-secret file is missing or invalid.");
            }

            var value = File.ReadAllText(file.FullName).Trim();
            return string.IsNullOrWhiteSpace(value)
                ? throw new InvalidOperationException("The configured WNS client-secret file is empty.")
                : value;
        }

        return !string.IsNullOrWhiteSpace(configured.WnsClientSecret)
            ? configured.WnsClientSecret.Trim()
            : throw new InvalidOperationException("WNS client credentials are not configured.");
    }

    private sealed record WnsOAuthToken(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("expires_in")] long ExpiresIn);
}

public sealed class WnsPushProvider(
    IHttpClientFactory httpClientFactory,
    IWnsAccessTokenProvider tokenProvider,
    TimeProvider timeProvider) : IPlatformPushProvider
{
    private const int MaxRawPayloadBytes = 5_000;
    private static readonly TimeSpan MaxTtl = TimeSpan.FromDays(28);

    public string Service => "wns";
    public bool IsReady => tokenProvider.IsConfigured;

    public async Task<ProviderResult> SendAsync(
        PushSubscription subscription,
        PushDelivery delivery,
        IReadOnlyDictionary<string, string> payload,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(subscription.Service, Service, StringComparison.Ordinal) ||
            !WnsChannelUriValidator.IsValid(subscription.DeviceToken))
        {
            return new(false, true, Error: "Invalid WNS subscription", InvalidateSubscription: true);
        }

        if (payload.Count != 2 || !payload.TryGetValue("enc_payload", out var encryptedPayload) ||
            !payload.TryGetValue("spns", out var version) ||
            version != PushEnvelopeCrypto.EnvelopeVersion.ToString() ||
            string.IsNullOrWhiteSpace(encryptedPayload) || encryptedPayload.Length > 8192)
        {
            return new(false, true, Error: "Invalid encrypted push payload");
        }

        var body = JsonSerializer.SerializeToUtf8Bytes(payload);
        if (body.Length > MaxRawPayloadBytes)
        {
            return new(false, true, Error: "Encrypted WNS payload exceeds the raw notification limit");
        }

        var accessToken = await tokenProvider.GetTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return new(false, false, Error: "WNS access token is unavailable");
        }

        var ttl = ResolveTtl(delivery.Expiration, timeProvider.GetUtcNow());
        var result = await SendCoreAsync(subscription.DeviceToken, body, accessToken, ttl, cancellationToken);
        if (result.StatusCode == HttpStatusCode.Unauthorized)
        {
            tokenProvider.Invalidate();
            accessToken = await tokenProvider.GetTokenAsync(cancellationToken);
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                result = await SendCoreAsync(subscription.DeviceToken, body, accessToken, ttl, cancellationToken);
            }
        }

        var success = result.StatusCode == HttpStatusCode.OK;
        var invalidateSubscription = result.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone;
        var permanent = invalidateSubscription || result.StatusCode is HttpStatusCode.BadRequest or
            HttpStatusCode.MethodNotAllowed or HttpStatusCode.RequestEntityTooLarge;
        return new(
            success,
            permanent,
            MessageId: result.TrackingId,
            Error: success ? null : $"WNS HTTP {(int)result.StatusCode}",
            InvalidateSubscription: invalidateSubscription,
            RetryAfter: success || permanent ? null : result.RetryAfter);
    }

    private async Task<WnsSendResult> SendCoreAsync(
        string channelUri,
        byte[] body,
        string accessToken,
        TimeSpan ttl,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, channelUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.TryAddWithoutValidation("X-WNS-Type", "wns/raw");
        request.Headers.TryAddWithoutValidation("X-WNS-Cache-Policy", "cache");
        request.Headers.TryAddWithoutValidation("X-WNS-RequestForStatus", "true");
        request.Headers.TryAddWithoutValidation(
            "X-WNS-TTL",
            Math.Max(0, (long)ttl.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using var response = await httpClientFactory
            .CreateClient("WnsDelivery")
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var trackingId = response.Headers.TryGetValues("X-WNS-MSG-ID", out var values)
            ? values.FirstOrDefault()
            : null;
        var retryAfter = response.Headers.RetryAfter?.Delta;
        if (retryAfter is null && response.Headers.RetryAfter?.Date is { } retryAt)
        {
            retryAfter = retryAt - timeProvider.GetUtcNow();
        }

        return new(response.StatusCode, trackingId, retryAfter > TimeSpan.Zero ? retryAfter : null);
    }

    private static TimeSpan ResolveTtl(long expiration, DateTimeOffset now)
    {
        var expirationSeconds = expiration >= 10_000_000_000L ? expiration / 1_000L : expiration;
        DateTimeOffset expiresAt;
        try
        {
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(expirationSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return TimeSpan.Zero;
        }

        var ttl = expiresAt - now;
        return ttl <= TimeSpan.Zero ? TimeSpan.Zero : ttl > MaxTtl ? MaxTtl : ttl;
    }

    private sealed record WnsSendResult(
        HttpStatusCode StatusCode,
        string? TrackingId,
        TimeSpan? RetryAfter);
}

public static class WnsChannelUriValidator
{
    public static bool IsValid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo) ||
            !uri.IsDefaultPort || string.IsNullOrEmpty(uri.Query))
        {
            return false;
        }

        return uri.Host.Equals("notify.windows.com", StringComparison.OrdinalIgnoreCase) ||
               uri.Host.EndsWith(".notify.windows.com", StringComparison.OrdinalIgnoreCase);
    }
}
