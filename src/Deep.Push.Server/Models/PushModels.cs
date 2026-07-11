using System.Text.Json;
using System.Text.Json.Serialization;

namespace Deep.Push.Server.Models;

public sealed record ServiceInfo([property: JsonPropertyName("token")] string Token);

public sealed record SubscribeRequest(
    [property: JsonPropertyName("pubkey")] string Pubkey,
    [property: JsonPropertyName("session_ed25519")] string SessionEd25519,
    [property: JsonPropertyName("namespaces")] IReadOnlyList<int> Namespaces,
    [property: JsonPropertyName("data")] bool Data,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("sig_ts")] long SigTs,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("service_info")] ServiceInfo ServiceInfo,
    [property: JsonPropertyName("enc_key")] string EncKey,
    [property: JsonPropertyName("app_id")] string AppId,
    [property: JsonPropertyName("app_version")] string AppVersion,
    [property: JsonPropertyName("sig_v")] int SigVersion);

public sealed record UnsubscribeRequest(
    [property: JsonPropertyName("pubkey")] string Pubkey,
    [property: JsonPropertyName("session_ed25519")] string SessionEd25519,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("sig_ts")] long SigTs,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("service_info")] ServiceInfo ServiceInfo,
    [property: JsonPropertyName("sig_v")] int SigVersion);

public sealed record NotifyRequest(
    [property: JsonPropertyName("pubkey")] string Pubkey,
    [property: JsonPropertyName("hash")] string Hash,
    [property: JsonPropertyName("namespace")] int Namespace,
    [property: JsonPropertyName("timestamp")] long Timestamp,
    [property: JsonPropertyName("expiration")] long Expiration,
    [property: JsonPropertyName("data")] string? Data)
{
    public bool IsValid() =>
        !string.IsNullOrWhiteSpace(Pubkey) &&
        !string.IsNullOrWhiteSpace(Hash) &&
        Timestamp > 0 &&
        Expiration > Timestamp &&
        (Data is null || Data.Length <= 8192);
}

public sealed record OperationResponse(
    [property: JsonPropertyName("success")] bool Success,
    [property: JsonPropertyName("error")] int Error,
    [property: JsonPropertyName("message")] string? Message = null,
    [property: JsonPropertyName("added")] bool? Added = null,
    [property: JsonPropertyName("removed")] bool? Removed = null);

public static class PushJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}
