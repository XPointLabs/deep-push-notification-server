using System.Text;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Push.Server.Security;

public static class SubscriptionSignatureVerifier
{
    public static bool VerifySubscribe(string pubkey, string ed25519, long timestamp, bool data, IReadOnlyList<int> namespaces, string signature)
    {
        var suffix = string.Join(',', namespaces);
        return Verify(pubkey, ed25519, signature, $"MONITOR{pubkey}{timestamp}{(data ? 1 : 0)}{suffix}");
    }

    public static bool VerifyUnsubscribe(string pubkey, string ed25519, long timestamp, string signature) =>
        Verify(pubkey, ed25519, signature, $"UNSUBSCRIBE{pubkey}{timestamp}");

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
