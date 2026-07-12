using System.Net;
using System.Text;
using System.Text.Json;
using Deep.Push.Server.Data;
using Deep.Push.Server.Services;

namespace Deep.Push.Server.Tests;

public sealed class WnsPushProviderTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    [Fact]
    public async Task Send_UsesRawEncryptedPayloadAndBearerToken()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Headers = { { "X-WNS-MSG-ID", "message-id" } }
        });
        var provider = new WnsPushProvider(
            new FixedHttpClientFactory(new HttpClient(handler)),
            new FixedTokenProvider("access-token"),
            new FixedTimeProvider(Now));
        var subscription = CreateSubscription("https://wns2-by3p.notify.windows.com/?token=opaque");

        var result = await provider.SendAsync(
            subscription,
            CreateDelivery(subscription, Now.AddHours(1)),
            new Dictionary<string, string>
            {
                ["enc_payload"] = "AQID",
                ["spns"] = "1"
            },
            default);

        Assert.True(result.Success);
        Assert.Equal("message-id", result.MessageId);
        Assert.NotNull(handler.Request);
        Assert.Equal("Bearer", handler.Request!.AuthorizationScheme);
        Assert.Equal("access-token", handler.Request.AuthorizationParameter);
        Assert.Equal("wns/raw", handler.Request.WnsType);
        Assert.Equal("application/octet-stream", handler.Request.ContentType);
        Assert.Equal("3600", handler.Request.Ttl);
        var body = JsonSerializer.Deserialize<Dictionary<string, string>>(handler.Request.Body);
        Assert.Equal("AQID", body!["enc_payload"]);
        Assert.Equal("1", body["spns"]);
        Assert.DoesNotContain("message", handler.Request.Body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Send_RejectsNonWnsHostWithoutNetworkRequest()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var provider = new WnsPushProvider(
            new FixedHttpClientFactory(new HttpClient(handler)),
            new FixedTokenProvider("access-token"),
            new FixedTimeProvider(Now));
        var subscription = CreateSubscription("https://notify.windows.com.evil.example/?token=opaque");

        var result = await provider.SendAsync(
            subscription,
            CreateDelivery(subscription, Now.AddHours(1)),
            new Dictionary<string, string> { ["enc_payload"] = "AQID", ["spns"] = "1" },
            default);

        Assert.False(result.Success);
        Assert.True(result.PermanentFailure);
        Assert.True(result.InvalidateSubscription);
        Assert.Null(handler.Request);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest, true, false)]
    [InlineData(HttpStatusCode.MethodNotAllowed, true, false)]
    [InlineData(HttpStatusCode.RequestEntityTooLarge, true, false)]
    [InlineData(HttpStatusCode.Forbidden, false, false)]
    [InlineData(HttpStatusCode.NotFound, true, true)]
    [InlineData(HttpStatusCode.Gone, true, true)]
    [InlineData(HttpStatusCode.ServiceUnavailable, false, false)]
    public async Task Send_ClassifiesDeliveryAndChannelFailuresSeparately(
        HttpStatusCode statusCode,
        bool permanent,
        bool invalidateSubscription)
    {
        var handler = new RecordingHandler(new HttpResponseMessage(statusCode));
        var provider = new WnsPushProvider(
            new FixedHttpClientFactory(new HttpClient(handler)),
            new FixedTokenProvider("access-token"),
            new FixedTimeProvider(Now));
        var subscription = CreateSubscription("https://wns2-by3p.notify.windows.com/?token=opaque");

        var result = await provider.SendAsync(
            subscription,
            CreateDelivery(subscription, Now.AddHours(1)),
            new Dictionary<string, string> { ["enc_payload"] = "AQID", ["spns"] = "1" },
            default);

        Assert.False(result.Success);
        Assert.Equal(permanent, result.PermanentFailure);
        Assert.Equal(invalidateSubscription, result.InvalidateSubscription);
    }

    private static PushSubscription CreateSubscription(string token) => new()
    {
        Id = Guid.NewGuid(),
        IdentityKey = "identity",
        Pubkey = "05" + new string('1', 64),
        SessionEd25519 = new string('2', 64),
        NamespacesJson = "[0]",
        WantData = true,
        Service = "wns",
        DeviceToken = token,
        EncryptionKey = new string('3', 64)
    };

    private static PushDelivery CreateDelivery(PushSubscription subscription, DateTimeOffset expiresAt) => new()
    {
        Id = Guid.NewGuid(),
        SubscriptionId = subscription.Id,
        Subscription = subscription,
        MessageHash = "hash",
        Namespace = 0,
        MessageTimestamp = Now.ToUnixTimeSeconds(),
        Expiration = expiresAt.ToUnixTimeSeconds(),
        Status = DeliveryStatus.Pending
    };

    private sealed class FixedTokenProvider(string token) : IWnsAccessTokenProvider
    {
        public bool IsConfigured => true;
        public Task<string?> GetTokenAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(token);
        public void Invalidate() { }
    }

    private sealed class FixedHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class RecordingHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public RecordedRequest? Request { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Request = new(
                request.RequestUri,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter,
                request.Headers.TryGetValues("X-WNS-Type", out var values) ? values.Single() : null,
                request.Headers.TryGetValues("X-WNS-TTL", out var ttlValues) ? ttlValues.Single() : null,
                request.Content?.Headers.ContentType?.MediaType,
                request.Content is null
                    ? string.Empty
                    : await request.Content.ReadAsStringAsync(cancellationToken));
            return response;
        }
    }

    private sealed record RecordedRequest(
        Uri? Uri,
        string? AuthorizationScheme,
        string? AuthorizationParameter,
        string? WnsType,
        string? Ttl,
        string? ContentType,
        string Body);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
