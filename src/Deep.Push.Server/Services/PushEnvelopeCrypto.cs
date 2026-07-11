using System.Security.Cryptography;
using System.Text;

namespace Deep.Push.Server.Services;

public static class PushEnvelopeCrypto
{
    public const string PackageName = "network.xpoint.deep";
    public const string EnvelopeProtocolVersion = "1";
    public const byte EnvelopeVersion = 1;
    public const int KeySizeBytes = 32;
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;
    public const int MaxPlaintextBytes = 2048;
    public const int MaxEnvelopeBytes = 4096;
    public const int MaxMessageDataBytes = 1024;
    public const int MaxMessageHashChars = 128;

    public static byte[] Encrypt(byte[] plaintext, byte[] key, string subscriptionBinding, string sessionBinding)
    {
        if (key.Length != KeySizeBytes)
        {
            throw new ArgumentException("Push encryption key must be 256 bits.", nameof(key));
        }

        ValidateBindings(subscriptionBinding, sessionBinding);
        if (plaintext.Length == 0 || plaintext.Length > MaxPlaintextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext));
        }

        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];
        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, CreateAssociatedData(subscriptionBinding, sessionBinding));

        var envelope = new byte[1 + nonce.Length + ciphertext.Length + tag.Length];
        envelope[0] = EnvelopeVersion;
        Buffer.BlockCopy(nonce, 0, envelope, 1, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, envelope, 1 + nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, envelope, 1 + nonce.Length + ciphertext.Length, tag.Length);
        if (envelope.Length > MaxEnvelopeBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext));
        }

        return envelope;
    }

    public static string ComputeSubscriptionBinding(string sessionId, string service, string token)
    {
        var material = $"deep.push/subscription/v1|session={sessionId.Trim().ToLowerInvariant()}|service={service.Trim().ToLowerInvariant()}|token={token.Trim()}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    public static bool TryDecrypt(byte[] envelope, byte[] key, string subscriptionBinding, string sessionBinding, out byte[] plaintext)
    {
        plaintext = [];
        try
        {
            if (key.Length != KeySizeBytes || envelope.Length < 1 + NonceSizeBytes + TagSizeBytes ||
                envelope.Length > MaxEnvelopeBytes || envelope[0] != EnvelopeVersion)
            {
                return false;
            }

            var ciphertextLength = envelope.Length - 1 - NonceSizeBytes - TagSizeBytes;
            if (ciphertextLength <= 0 || ciphertextLength > MaxPlaintextBytes)
            {
                return false;
            }

            var nonce = envelope.AsSpan(1, NonceSizeBytes);
            var ciphertext = envelope.AsSpan(1 + NonceSizeBytes, ciphertextLength);
            var tag = envelope.AsSpan(1 + NonceSizeBytes + ciphertextLength, TagSizeBytes);
            plaintext = new byte[ciphertextLength];
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, CreateAssociatedData(subscriptionBinding, sessionBinding));
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            plaintext = [];
            return false;
        }
        catch (ArgumentException)
        {
            plaintext = [];
            return false;
        }
    }

    private static byte[] CreateAssociatedData(string subscriptionBinding, string sessionBinding)
    {
        ValidateBindings(subscriptionBinding, sessionBinding);
        return Encoding.UTF8.GetBytes($"deep.push/envelope/v1|package={PackageName}|protocol={EnvelopeProtocolVersion}|subscription={subscriptionBinding}|session={sessionBinding}");
    }

    private static void ValidateBindings(string subscriptionBinding, string sessionBinding)
    {
        if (string.IsNullOrWhiteSpace(subscriptionBinding) || string.IsNullOrWhiteSpace(sessionBinding) ||
            subscriptionBinding.Length > 128 || sessionBinding.Length > 128)
        {
            throw new ArgumentException("Push envelope bindings are invalid.");
        }
    }
}
