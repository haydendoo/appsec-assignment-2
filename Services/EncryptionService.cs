using System.Security.Cryptography;
using System.Text;

namespace appsec_assignment_2.Services;

public class EncryptionService
{
    private const int AesBlockSizeBytes = 16;
    private readonly byte[] _key;

    public EncryptionService(IConfiguration configuration)
    {
        var keyString = configuration["Encryption:Key"]
            ?? throw new InvalidOperationException("Encryption key not configured");

        using var sha256 = SHA256.Create();
        _key = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        var iv = new byte[AesBlockSizeBytes];
        RandomNumberGenerator.Fill(iv);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        var payload = new byte[iv.Length + encryptedBytes.Length];
        Buffer.BlockCopy(iv, 0, payload, 0, iv.Length);
        Buffer.BlockCopy(encryptedBytes, 0, payload, iv.Length, encryptedBytes.Length);

        return Convert.ToBase64String(payload);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        var payload = Convert.FromBase64String(cipherText);
        if (payload.Length < AesBlockSizeBytes)
            throw new CryptographicException("Invalid cipher text format.");

        var iv = new byte[AesBlockSizeBytes];
        var encryptedBytes = new byte[payload.Length - AesBlockSizeBytes];
        Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(payload, AesBlockSizeBytes, encryptedBytes, 0, encryptedBytes.Length);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public string? TryDecrypt(string? cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        try
        {
            return Decrypt(cipherText);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public byte[] EncryptBytes(byte[] plainBytes)
    {
        if (plainBytes == null || plainBytes.Length == 0)
            return Array.Empty<byte>();

        var iv = new byte[AesBlockSizeBytes];
        RandomNumberGenerator.Fill(iv);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        var payload = new byte[iv.Length + encryptedBytes.Length];
        Buffer.BlockCopy(iv, 0, payload, 0, iv.Length);
        Buffer.BlockCopy(encryptedBytes, 0, payload, iv.Length, encryptedBytes.Length);

        return payload;
    }

    public byte[] DecryptBytes(byte[] payload)
    {
        if (payload == null || payload.Length < AesBlockSizeBytes)
            throw new CryptographicException("Invalid cipher text format.");

        var iv = new byte[AesBlockSizeBytes];
        var encryptedBytes = new byte[payload.Length - AesBlockSizeBytes];
        Buffer.BlockCopy(payload, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(payload, AesBlockSizeBytes, encryptedBytes, 0, encryptedBytes.Length);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
    }
}
