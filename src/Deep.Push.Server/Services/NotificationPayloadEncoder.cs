using System.Text.Json;
using Deep.Push.Server.Data;

namespace Deep.Push.Server.Services;

public sealed class NotificationPayloadEncoder
{
    public IReadOnlyDictionary<string, string> Encode(PushSubscription subscription, PushDelivery delivery)
    {
        var data = subscription.WantData && !string.IsNullOrEmpty(delivery.MessageData)
            ? DecodeBody(delivery.MessageData)
            : null;
        var plaintext = SerializeNotification(delivery, data);
        if (plaintext.Length > PushEnvelopeCrypto.MaxPlaintextBytes)
        {
            data = null;
            plaintext = SerializeNotification(delivery, data);
        }

        if (plaintext.Length > PushEnvelopeCrypto.MaxPlaintextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(delivery.MessageHash));
        }

        var key = Convert.FromHexString(subscription.EncryptionKey);
        var binding = PushEnvelopeCrypto.ComputeSubscriptionBinding(subscription.Pubkey, subscription.Service, subscription.DeviceToken);
        var payload = PushEnvelopeCrypto.Encrypt(plaintext, key, binding, subscription.Pubkey);
        var encodedPayload = Convert.ToBase64String(payload);
        if (encodedPayload.Length > 8192)
        {
            throw new ArgumentOutOfRangeException(nameof(delivery.MessageData));
        }

        return new Dictionary<string, string>
        {
            ["enc_payload"] = encodedPayload,
            ["spns"] = PushEnvelopeCrypto.EnvelopeVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
    }

    private static byte[] DecodeBody(string value)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            bytes = System.Text.Encoding.UTF8.GetBytes(value);
        }

        return bytes.Length <= PushEnvelopeCrypto.MaxMessageDataBytes ? bytes : [];
    }

    private static byte[] SerializeNotification(PushDelivery delivery, byte[]? data) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            message_hash = delivery.MessageHash,
            @namespace = delivery.Namespace,
            timestamp = delivery.MessageTimestamp,
            expiration = delivery.Expiration,
            data = data is { Length: > 0 } ? Convert.ToBase64String(data) : null
        });
}
