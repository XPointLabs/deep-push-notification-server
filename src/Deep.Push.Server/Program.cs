using System.Text.Json;
using Deep.Push.Server.Data;
using Deep.Push.Server.Models;
using Deep.Push.Server.Security;
using Deep.Push.Server.Services;
using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks().AddDbContextCheck<PushDbContext>();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("subscriptions", limiter =>
    {
        limiter.PermitLimit = 60;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
    });
});

builder.Services
    .AddOptions<PushOptions>()
    .Bind(builder.Configuration.GetSection(PushOptions.Section))
    .Validate(
        static options => !options.WnsEnabled || options.IsWnsConfigured,
        "Enabled WNS requires valid tenant/client GUIDs and exactly one bounded client-secret source. The configured secret file must exist.")
    .ValidateOnStart();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpClient<NodeRegistryClient>();
builder.Services.AddHttpClient("WnsOAuth", client =>
{
    client.BaseAddress = new Uri("https://login.microsoftonline.com/");
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddHttpClient("WnsDelivery", client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<SubscriptionService>();
builder.Services.AddScoped<NotifyAuthorizationService>();
builder.Services.AddSingleton<NotificationPayloadEncoder>();

var connectionString = DatabaseConfiguration.BuildConnectionString(builder.Configuration);
builder.Services.AddDbContext<PushDbContext>(options => options.UseNpgsql(connectionString));

var firebaseCredentialsPath = builder.Configuration[$"{PushOptions.Section}:FirebaseCredentialsPath"];
if (!string.IsNullOrWhiteSpace(firebaseCredentialsPath))
{
    builder.Services.AddSingleton(_ => FirebaseApp.Create(new AppOptions
    {
        Credential = CredentialFactory.FromFile<ServiceAccountCredential>(firebaseCredentialsPath).ToGoogleCredential()
    }));
    builder.Services.AddSingleton<IPlatformPushProvider, FirebasePushProvider>();
}

builder.Services.AddSingleton<IWnsAccessTokenProvider, WnsAccessTokenProvider>();
builder.Services.AddSingleton<IPlatformPushProvider, WnsPushProvider>();
builder.Services.AddSingleton<IPushProvider, PushProviderRouter>();

builder.Services.AddHostedService<DeliveryWorker>();

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});
app.UseExceptionHandler();
app.UseRateLimiter();

await DatabaseConfiguration.MigrateAsync(app.Services);

app.MapGet("/health/live", () => Results.Ok(new { status = "ok", service = "deep-push" }));
app.MapHealthChecks("/health/ready");

app.MapPost("/subscribe", async (JsonElement payload, SubscriptionService subscriptions, CancellationToken cancellationToken) =>
    Results.Json(await subscriptions.SubscribeAsync(payload, cancellationToken)))
    .RequireRateLimiting("subscriptions");

app.MapPost("/unsubscribe", async (JsonElement payload, SubscriptionService subscriptions, CancellationToken cancellationToken) =>
    Results.Json(await subscriptions.UnsubscribeAsync(payload, cancellationToken)))
    .RequireRateLimiting("subscriptions");

app.MapPost("/_compat/push-notify", async (
    HttpRequest request,
    NotifyAuthorizationService authorization,
    SubscriptionService subscriptions,
    CancellationToken cancellationToken) =>
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync(cancellationToken);
    if (!await authorization.IsAuthorizedAsync(request.Headers, body, cancellationToken))
    {
        return Results.Unauthorized();
    }

    NotifyRequest? notification;
    try
    {
        notification = JsonSerializer.Deserialize<NotifyRequest>(body, PushJson.Options);
    }
    catch (JsonException)
    {
        return Results.BadRequest(new { error = "invalid-json" });
    }

    if (notification is null || !notification.IsValid())
    {
        return Results.BadRequest(new { error = "invalid-notification" });
    }

    var queued = await subscriptions.QueueNotificationAsync(notification, cancellationToken);
    return Results.Accepted(value: new { queued });
});

app.MapGet("/stats", async (PushDbContext db, CancellationToken cancellationToken) => Results.Ok(new
{
    subscriptions = await db.Subscriptions.CountAsync(cancellationToken),
    pending = await db.Deliveries.CountAsync(x => x.Status == DeliveryStatus.Pending || x.Status == DeliveryStatus.Retry, cancellationToken),
    delivered = await db.Deliveries.CountAsync(x => x.Status == DeliveryStatus.Delivered, cancellationToken),
    failed = await db.Deliveries.CountAsync(x => x.Status == DeliveryStatus.Failed, cancellationToken)
}));

app.Run();

public partial class Program;
