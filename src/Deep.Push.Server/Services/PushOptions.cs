namespace Deep.Push.Server.Services;

public sealed class PushOptions
{
    public const string Section = "Push";
    public string? FirebaseCredentialsPath { get; set; }
    public bool WnsEnabled { get; set; }
    public string? WnsTenantId { get; set; }
    public string? WnsClientId { get; set; }
    public string? WnsClientSecretFile { get; set; }
    public string? WnsClientSecret { get; set; }
    public string RegistryUrl { get; set; } = "https://registry.xpoint.network";
    public int MaxAttempts { get; set; } = 8;
    public int BatchSize { get; set; } = 100;
    public int WorkerIntervalMilliseconds { get; set; } = 500;

    public bool IsWnsConfigured =>
        WnsEnabled &&
        Guid.TryParse(WnsTenantId, out var tenantId) && tenantId != Guid.Empty &&
        Guid.TryParse(WnsClientId, out var clientId) && clientId != Guid.Empty &&
        HasExactlyOneWnsSecret && IsWnsSecretSourceValid();

    public bool HasExactlyOneWnsSecret =>
        !string.IsNullOrWhiteSpace(WnsClientSecretFile) ^ !string.IsNullOrWhiteSpace(WnsClientSecret);

    public bool IsWnsSecretSourceValid()
    {
        if (!string.IsNullOrWhiteSpace(WnsClientSecret))
        {
            var value = WnsClientSecret.Trim();
            return value.Length is > 0 and <= 16_384;
        }

        if (string.IsNullOrWhiteSpace(WnsClientSecretFile))
        {
            return false;
        }

        var file = new FileInfo(WnsClientSecretFile);
        return file.Exists && file.Length is > 0 and <= 16_384;
    }
}
