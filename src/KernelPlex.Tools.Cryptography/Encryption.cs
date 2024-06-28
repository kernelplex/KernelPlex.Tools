namespace KernelPlex.Tools.Cryptography;
using System.Security.Cryptography;
using System.Text;

public static class Encryption
{
    /// <summary>
    /// Size of the Initialization Vector (IV) used for encryption.
    /// </summary>
    public const int IV_SIZE = 16;

    /// <summary>
    /// Encrypts a plain text string using the provided key.
    /// </summary>
    /// <param name="plainText">The plain text to be encrypted.</param>
    /// <param name="key">The encryption key.</param>
    /// <returns>The encrypted string.</returns>
    public static string EncryptString(string plainText, byte[] key)
    {
        var sourceBytes = Encoding.UTF8.GetBytes(plainText);
        var encrypted = Encrypt(sourceBytes, key);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Encrypts a byte array using the provided key and returns the encrypted byte array.
    /// </summary>
    /// <param name="sourceBytes">The byte array to be encrypted.</param>
    /// <param name="key">The encryption key.</param>
    /// <returns>The encrypted byte array.</returns>
    private static byte[] Encrypt(byte[] sourceBytes, byte[] key)
    {
        var iv = RandomNumberGenerator.GetBytes(IV_SIZE);
        using var aesAlg = Aes.Create();
        var encryptor = aesAlg.CreateEncryptor(key, iv);
        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
        cryptoStream.Write(sourceBytes, 0, sourceBytes.Length);
        cryptoStream.Flush();
        cryptoStream.Close();
        var encryptedBytes = memoryStream.ToArray();
        
        
        var ivAndEncryptedBytes = new byte[encryptedBytes.Length + IV_SIZE];
        Array.Copy(iv, 0, ivAndEncryptedBytes, 0, IV_SIZE);
        Array.Copy(encryptedBytes, 0, ivAndEncryptedBytes, IV_SIZE, encryptedBytes.Length);
        return ivAndEncryptedBytes;
    }

    /// <summary>
    /// Decrypts an encrypted string using the provided key.
    /// </summary>
    /// <param name="source">The encrypted string to be decrypted.</param>
    /// <param name="key">The decryption key.</param>
    /// <returns>The decrypted string.</returns>
    public static string DecryptString(string source, byte[] key)
    {
        var decryptedBytes = Decrypt(source, key);
        return Encoding.UTF8.GetString(decryptedBytes);
    }


    /// <summary>
    /// Decrypts an encrypted string using the provided key.
    /// </summary>
    /// <param name="source">The encrypted string to be decrypted.</param>
    /// <param name="key">The decryption key.</param>
    /// <returns>The decrypted string.</returns>
    public static byte[] Decrypt(string source, byte[] key)
    {
        var sourceBytes = Convert.FromBase64String(source);
        return Decrypt(sourceBytes, key);
    }


    /// <summary>
    /// Decrypts an encrypted string using the provided key.
    /// </summary>
    /// <param name="sourceBytes"></param>
    /// <param name="key">The decryption key.</param>
    /// <returns>The decrypted string.</returns>
    public static byte[] Decrypt(byte[] sourceBytes, byte[] key)
    {
        var iv = new byte[IV_SIZE];
        var encryptedLength = sourceBytes.Length - IV_SIZE;
        var encryptedBytes = new byte[encryptedLength];

        Array.Copy(sourceBytes, 0, iv, 0, IV_SIZE);
        Array.Copy(sourceBytes, IV_SIZE, encryptedBytes, 0, encryptedLength);
        using var aesAlg = Aes.Create();
        var decryptionTransform = aesAlg.CreateDecryptor(key, iv);
        using var encryptedBytesStream = new MemoryStream(encryptedBytes);
        var decryptionStream = new CryptoStream(encryptedBytesStream, decryptionTransform, CryptoStreamMode.Read);
        var plainStream = new MemoryStream();
        decryptionStream.CopyTo(plainStream);
        decryptionStream.Close();
        return plainStream.ToArray();
    }
}
