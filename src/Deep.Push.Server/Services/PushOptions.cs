namespace Deep.Push.Server.Services;

public sealed class PushOptions
{
    public const string Section = "Push";
    public string? FirebaseCredentialsPath { get; set; }
    public string RegistryUrl { get; set; } = "https://registry.xpoint.network";
    public int MaxAttempts { get; set; } = 8;
    public int BatchSize { get; set; } = 100;
    public int WorkerIntervalMilliseconds { get; set; } = 500;
}
