namespace KernelPlex.Tools.Cryptography;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

/// <summary>
/// Provides methods for generating and verifying hashed password, as well as generating random spice.
/// </summary>
public static class HashGenerator
{
    
    /// <summary>
    /// Can be used to generate salt and pepper.
    /// </summary>
    /// <param name="size"></param>
    /// <returns></returns>
    public static byte[] GenerateSpice(int size = 32)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    /// <summary>
    /// Verifies whether a given hashed password matches the provided password.
    /// </summary>
    /// <param name="hashedPassword">The hashed password to be verified.</param>
    /// <param name="password">The password to check against the hashed password.</param>
    /// <returns>True if the password matches the hashed password; otherwise, false.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the password hash does not contain salt.</exception>
    public static bool Verify(string hashedPassword, string password)
    {
        var split = hashedPassword.Split('$', 2);
        if (split.Length != 2)
        {
            throw new InvalidOperationException("Password hash does not contain salt.");
        }
        
        var salt64 = split[1];
        var saltBytes = Convert.FromBase64String(salt64);
        var passwordBytes = Encoding.UTF8.GetBytes(password); 
        var verifiedHash = HashPassword(passwordBytes, saltBytes);
        return verifiedHash == hashedPassword;
    }

    /// <summary>
    /// Verifies a hashed password with the provided password and pepper bytes.
    /// </summary>
    /// <param name="hashedPassword">The hashed password to be verified.</param>
    /// <param name="password">The password to check against the hashed password.</param>
    /// <param name="pepperBytes">The bytes used as pepper in the hashing process.</param>
    /// <returns>True if the password matches the hashed password, otherwise false.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the hashed password does not contain salt.</exception>
    public static bool Verify(string hashedPassword, string password, byte[] pepperBytes)
    {
        var split = hashedPassword.Split('$', 2);
        if (split.Length != 2)
        {
            throw new InvalidOperationException("Password hash does not contain salt.");
        }
        
        var salt64 = split[1];
        var saltBytes = Convert.FromBase64String(salt64);
        var passwordBytes = Encoding.UTF8.GetBytes(password); 
        var verifiedHash = HashPassword(passwordBytes, saltBytes, pepperBytes);
        return verifiedHash == hashedPassword;
    }

    /// <summary>
    /// Hashes a password using salt and pepper.
    /// </summary>
    /// <param name="password">The password to be hashed.</param>
    /// <param name="pepperBytes">The pepper bytes to be included in the hash.</param>
    /// <returns>The hashed password.</returns>
    public static string HashPassword(string password, byte[] pepperBytes)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = GenerateSpice();
        return HashPassword(passwordBytes, saltBytes, pepperBytes);
    }

    /// <summary>
    /// Hashes a password using Argon2id algorithm and generates a unique salt.
    /// </summary>
    /// <param name="password">The password to be hashed.</param>
    /// <returns>The hashed password concatenated with the generated salt.</returns>
    public static string HashPassword(string password)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = GenerateSpice();
        return HashPassword(passwordBytes, saltBytes);
    }

    /// <summary>
    /// Hashes a password using Argon2id with salt and pepper.
    /// </summary>
    /// <param name="passwordBytes">The password to be hashed, represented as a byte array.</param>
    /// <param name="saltBytes">The salt to be used for password hashing, represented as a byte array.</param>
    /// <param name="pepperBytes">The pepper to be used for password hashing, represented as a byte array.</param>
    /// <returns>The hashed password as a base64-encoded string, concatenated with the salt.</returns>
    public static string HashPassword(byte[] passwordBytes, byte[] saltBytes, byte[] pepperBytes)
    {
        var saltAndPepper = new byte[saltBytes.Length + pepperBytes.Length];
        Array.Copy(saltBytes, saltAndPepper, saltBytes.Length);
        Array.Copy(pepperBytes, 0, saltAndPepper, saltBytes.Length, pepperBytes.Length);
        return HashPassword(passwordBytes, saltBytes);
    }

    /// <summary>
    /// Hashes the provided password using the Argon2id algorithm with provided salt.
    /// </summary>
    /// <param name="passwordBytes">The password to be hashed in byte array format.</param>
    /// <param name="saltBytes">The salt to use for hashing in byte array format.</param>
    /// <param name="pepperBytes">The pepper to use for hashing in byte array format.</param>
            /// <returns>The hashed password string.</returns>
    private static string HashPassword(byte[] passwordBytes, byte[] spiceBytes)
    {
        var argon2id = new Argon2id(passwordBytes);
        argon2id.Iterations = 2;
        argon2id.MemorySize = 8192;
        argon2id.DegreeOfParallelism = 1;
        argon2id.Salt = spiceBytes;
        var digest = argon2id.GetBytes(24);
        return Convert.ToBase64String(digest) + "$" + Convert.ToBase64String(spiceBytes);
    }
}
