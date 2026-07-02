using System.Text;
using System.Text.Json;
using Deep.Push.Server.Data;
using Sodium;

namespace Deep.Push.Server.Services;

public sealed class NotificationPayloadEncoder
{
    private const int MaxBodyBytes = 2500;

    public IReadOnlyDictionary<string, string> Encode(PushSubscription subscription, PushDelivery delivery)
    {
        var body = subscription.WantData && !string.IsNullOrEmpty(delivery.MessageData)
            ? DecodeBody(delivery.MessageData)
            : null;
        var tooLarge = body?.Length > MaxBodyBytes;
        var metadata = new Dictionary<string, object>
        {
            ["@"] = subscription.Pubkey,
            ["#"] = delivery.MessageHash,
            ["n"] = delivery.Namespace,
            ["t"] = delivery.MessageTimestamp,
            ["z"] = delivery.Expiration
        };

        if (subscription.WantData)
        {
            metadata["l"] = body?.Length ?? 0;
            if (tooLarge) metadata["B"] = true;
        }

        var elements = new List<byte[]> { JsonSerializer.SerializeToUtf8Bytes(metadata) };
        if (body is { Length: > 0 } && !tooLarge) elements.Add(body);

        var plaintext = Pad(BencodeList(elements));
        var key = Convert.FromHexString(subscription.EncryptionKey);
        var nonce = SecretAeadXChaCha20Poly1305.GenerateNonce();
        var encrypted = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key, []);
        var payload = new byte[nonce.Length + encrypted.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(encrypted, 0, payload, nonce.Length, encrypted.Length);

        return new Dictionary<string, string>
        {
            ["enc_payload"] = Convert.ToBase64String(payload),
            ["spns"] = "1"
        };
    }

    private static byte[] DecodeBody(string value)
    {
        try { return Convert.FromBase64String(value); }
        catch (FormatException) { return Encoding.UTF8.GetBytes(value); }
    }

    private static byte[] BencodeList(IEnumerable<byte[]> values)
    {
        using var stream = new MemoryStream();
        stream.WriteByte((byte)'l');
        foreach (var value in values)
        {
            var length = Encoding.ASCII.GetBytes(value.Length.ToString());
            stream.Write(length);
            stream.WriteByte((byte)':');
            stream.Write(value);
        }
        stream.WriteByte((byte)'e');
        return stream.ToArray();
    }

    private static byte[] Pad(byte[] value)
    {
        var length = ((value.Length + 255) / 256) * 256;
        if (length == value.Length) return value;
        var padded = new byte[length];
        Buffer.BlockCopy(value, 0, padded, 0, value.Length);
        return padded;
    }
}
