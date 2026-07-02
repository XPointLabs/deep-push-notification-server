using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Push.Server.Services;

namespace Deep.Push.Server.Security;

public sealed class NotifyAuthorizationService(IConfiguration configuration, NodeRegistryClient registry, TimeProvider timeProvider)
{
    public async Task<bool> IsAuthorizedAsync(IHeaderDictionary headers, string body, CancellationToken cancellationToken)
    {
        var configuredToken = ReadSecret(configuration["Push:InternalTokenFile"], configuration["Push:InternalToken"]);
        var authorization = headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(configuredToken) && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var supplied = authorization[7..];
            if (FixedTimeEquals(configuredToken, supplied))
            {
                return true;
            }
        }

        var nodeId = headers["X-XPoint-Node-Id"].ToString().ToLowerInvariant();
        var timestampText = headers["X-XPoint-Notify-Timestamp"].ToString();
        var signatureText = headers["X-XPoint-Notify-Signature"].ToString();
        if (nodeId.Length != 64 || !nodeId.All(Uri.IsHexDigit) || !long.TryParse(timestampText, out var timestamp))
        {
            return false;
        }

        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (Math.Abs(now - timestamp) > 300)
        {
            return false;
        }

        var publicKey = await registry.GetActiveNodeKeyAsync(nodeId, cancellationToken);
        if (publicKey is null)
        {
            return false;
        }

        try
        {
            var bodyHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
            var canonical = Encoding.UTF8.GetBytes($"XPOINT_PUSH_NOTIFY_V1\n{nodeId}\n{timestamp}\n{bodyHash}");
            return Sodium.PublicKeyAuth.VerifyDetached(
                SubscriptionSignatureVerifier.Decode(signatureText, 64),
                canonical,
                Convert.FromHexString(publicKey));
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string? ReadSecret(string? path, string? fallback) =>
        !string.IsNullOrWhiteSpace(path) && File.Exists(path) ? File.ReadAllText(path).Trim() : fallback;

    private static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));
}
