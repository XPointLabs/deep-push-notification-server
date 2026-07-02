namespace Deep.Push.Server.Data;

public sealed class PushSubscription
{
    public Guid Id { get; set; }
    public required string IdentityKey { get; set; }
    public required string Pubkey { get; set; }
    public required string SessionEd25519 { get; set; }
    public required string NamespacesJson { get; set; }
    public bool WantData { get; set; }
    public required string Service { get; set; }
    public required string DeviceToken { get; set; }
    public required string EncryptionKey { get; set; }
    public long SignatureTimestamp { get; set; }
    public DateTimeOffset SubscribedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public ICollection<PushDelivery> Deliveries { get; set; } = [];
}

public sealed class PushDelivery
{
    public Guid Id { get; set; }
    public Guid SubscriptionId { get; set; }
    public PushSubscription Subscription { get; set; } = null!;
    public required string MessageHash { get; set; }
    public int Namespace { get; set; }
    public long MessageTimestamp { get; set; }
    public long Expiration { get; set; }
    public string? MessageData { get; set; }
    public DeliveryStatus Status { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DeliveredAt { get; set; }
    public string? ProviderMessageId { get; set; }
    public string? LastError { get; set; }
}

public enum DeliveryStatus
{
    Pending,
    Sending,
    Retry,
    Delivered,
    Failed
}
