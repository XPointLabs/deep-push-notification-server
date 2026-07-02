using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Deep.Push.Server.Services;

public sealed class NodeRegistryClient(HttpClient httpClient, IOptions<PushOptions> options, ILogger<NodeRegistryClient> logger)
{
    private IReadOnlyDictionary<string, string> cached = new Dictionary<string, string>();
    private DateTimeOffset cacheExpiresAt;
    private readonly SemaphoreSlim refreshLock = new(1, 1);

    public async Task<string?> GetActiveNodeKeyAsync(string nodeId, CancellationToken cancellationToken)
    {
        if (DateTimeOffset.UtcNow >= cacheExpiresAt)
        {
            await RefreshAsync(cancellationToken);
        }

        return cached.GetValueOrDefault(nodeId);
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            if (DateTimeOffset.UtcNow < cacheExpiresAt)
            {
                return;
            }

            using var response = await httpClient.GetAsync(new Uri(new Uri(options.Value.RegistryUrl), "/api/nodes"), cancellationToken);
            response.EnsureSuccessStatusCode();
            using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
            var nodes = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray()
                : document.RootElement.TryGetProperty("nodes", out var values) ? values.EnumerateArray() : [];

            cached = nodes
                .Where(IsActive)
                .Select(x => new
                {
                    Id = ReadString(x, "nodeId")?.ToLowerInvariant(),
                    Key = (ReadString(x, "ed25519PublicKey") ?? ReadString(x, "nodeId"))?.ToLowerInvariant()
                })
                .Where(x => x.Id?.Length == 64 && x.Key?.Length == 64)
                .ToDictionary(x => x.Id!, x => x.Key!);
            cacheExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1);
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Could not refresh the signed node catalog");
            cacheExpiresAt = DateTimeOffset.UtcNow.AddSeconds(10);
        }
        finally
        {
            refreshLock.Release();
        }
    }

    private static bool IsActive(JsonElement node)
    {
        if (node.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.False) return false;
        if (node.TryGetProperty("mocked", out var mocked) && mocked.ValueKind == JsonValueKind.True) return false;
        if (node.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String)
        {
            return status.GetString() is "active" or "running" or "online";
        }
        return true;
    }

    private static string? ReadString(JsonElement value, string name) =>
        value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String ? property.GetString() : null;
}
