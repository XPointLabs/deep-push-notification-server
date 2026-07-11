using System.Text;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Push.Server.Security;

public static class SubscriptionSignatureVerifier
{
    public const int SignatureVersion = 2;

    public static bool VerifySubscribe(
        int signatureVersion,
        string pubkey,
        string ed25519,
        long timestamp,
        bool data,
        IReadOnlyList<int> namespaces,
        string service,
        string deviceToken,
        string encryptionKey,
        string appId,
        string appVersion,
        string signature) =>
        signatureVersion == SignatureVersion &&
        Verify(
            pubkey,
            ed25519,
            signature,
            PushSubscriptionCanonicalFormat.CreateSubscribe(
                pubkey,
                timestamp,
                data,
                namespaces,
                service,
                deviceToken,
                encryptionKey,
                appId,
                appVersion));

    public static bool VerifyUnsubscribe(
        int signatureVersion,
        string pubkey,
        string ed25519,
        long timestamp,
        string service,
        string deviceToken,
        string signature) =>
        signatureVersion == SignatureVersion &&
        Verify(
            pubkey,
            ed25519,
            signature,
            PushSubscriptionCanonicalFormat.CreateUnsubscribe(pubkey, timestamp, service, deviceToken));

    private static bool Verify(string pubkey, string ed25519, string signature, string message)
    {
        try
        {
            if (pubkey.Length != 66 || !pubkey.StartsWith("05", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var edKey = Decode(ed25519, 32);
            var sig = Decode(signature, 64);
            var x25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(edKey);
            if (!CryptographicOperations.FixedTimeEquals(x25519, Convert.FromHexString(pubkey[2..])))
            {
                return false;
            }

            return PublicKeyAuth.VerifyDetached(sig, Encoding.UTF8.GetBytes(message), edKey);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static byte[] Decode(string value, int length)
    {
        byte[] decoded;
        if (value.Length == length * 2 && value.All(Uri.IsHexDigit))
        {
            decoded = Convert.FromHexString(value);
        }
        else
        {
            var normalized = value.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight((normalized.Length + 3) / 4 * 4, '=');
            decoded = Convert.FromBase64String(normalized);
        }

        return decoded.Length == length ? decoded : throw new FormatException("Unexpected key length.");
    }
}

internal static class PushSubscriptionCanonicalFormat
{
    public static string CreateSubscribe(
        string pubkey,
        long timestamp,
        bool wantData,
        IReadOnlyList<int> namespaces,
        string service,
        string deviceToken,
        string encryptionKey,
        string appId,
        string appVersion) =>
        Create(
            "subscribe",
            ("pubkey", pubkey),
            ("sig_ts", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("service", service),
            ("device_token", deviceToken),
            ("enc_key", encryptionKey),
            ("want_data", wantData ? "1" : "0"),
            ("namespaces", string.Join(',', namespaces.OrderBy(static value => value).Select(static value => value.ToString(System.Globalization.CultureInfo.InvariantCulture)))),
            ("app_id", appId),
            ("app_version", appVersion));

    public static string CreateUnsubscribe(
        string pubkey,
        long timestamp,
        string service,
        string deviceToken) =>
        Create(
            "unsubscribe",
            ("pubkey", pubkey),
            ("sig_ts", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("service", service),
            ("device_token", deviceToken));

    private static string Create(string operation, params (string Name, string Value)[] fields)
    {
        var builder = new StringBuilder($"deep.push/{operation}/v{SubscriptionSignatureVerifier.SignatureVersion}\n");
        foreach (var (name, value) in fields)
        {
            builder.Append(name)
                .Append('=')
                .Append(Encoding.UTF8.GetByteCount(value).ToString(System.Globalization.CultureInfo.InvariantCulture))
                .Append(':')
                .Append(value)
                .Append('\n');
        }

        return builder.ToString();
    }
}
