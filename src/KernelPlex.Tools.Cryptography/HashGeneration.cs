﻿namespace KernelPlex.Tools.Cryptography;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

/// <summary>
/// Provides methods for generating and verifying hashed password, as well as generating random spice.
/// </summary>
public static class HashGeneration
{
    public const char SaltDelimiter = '.'; 
    
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
    /// Generates a base64-encoded spice of the specified size.
    /// </summary>
    /// <param name="size">The size of the spice in bytes. Defaults to 32.</param>
    /// <returns>A base64-encoded string representing the generated spice.</returns>
    public static string GenerateBase64Spice(int size = 32)
    {
        var bytes = GenerateSpice(size);
        return Convert.ToBase64String(bytes);
    }


    /// <summary>
    /// Verifies a hashed password with the provided password and pepper bytes.
    /// </summary>
    /// <param name="hashedPassword">The hashed password to be verified.</param>
    /// <param name="password">The password to check against the hashed password.</param>
    /// <param name="base64Pepper">The base-64 pepper used to hash the password.</param>
    /// <returns>True if the password matches the hashed password, otherwise false.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the hashed password does not contain salt.</exception>
    public static bool Verify(string hashedPassword, string password, string base64Pepper)
    {
        var pepperBytes = Convert.FromBase64String(base64Pepper);
        return Verify(hashedPassword, password, pepperBytes);
    }


    /// <summary>
    /// Verifies a hashed password with the provided password and pepper bytes.
    /// </summary>
    /// <param name="hashedPassword">The hashed password to be verified.</param>
    /// <param name="password">The password to check against the hashed password.</param>
    /// <param name="pepperBytes">The bytes used as pepper in the hashing process.</param>
    /// <returns>True if the password matches the hashed password, otherwise false.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the hashed password does not contain salt.</exception>
    public static bool Verify(string hashedPassword, string password, byte[]? pepperBytes = null)
    {
        var split = hashedPassword.Split(SaltDelimiter, 2);
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
    /// <param name="base64Pepper">The base-64 pepper to use.</param>
    /// <returns>The hashed password.</returns>
    public static string HashPassword(string password, string base64Pepper)
    {
        var pepperBytes = Convert.FromBase64String(base64Pepper);
        return HashPassword(password, pepperBytes);
    }

    /// <summary>
    /// Hashes a password using Argon2id algorithm and generates a unique salt.
    /// </summary>
    /// <param name="password">The password to be hashed.</param>
    /// <param name="pepperBytes">The pepper bytes to be included in the hash.</param>
    /// <returns>The hashed password.</returns>
    public static string HashPassword(string password, byte[]? pepperBytes = null)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = GenerateSpice();
        return HashPassword(passwordBytes, saltBytes, pepperBytes);
    }

    /// <summary>
    /// Hashes a password using Argon2id with salt and pepper.
    /// </summary>
    /// <param name="passwordBytes">The password to be hashed, represented as a byte array.</param>
    /// <param name="saltBytes">The salt to be used for password hashing, represented as a byte array.</param>
    /// <param name="pepperBytes">The pepper to be used for password hashing, represented as a byte array.</param>
    /// <returns>The hashed password as a base64-encoded string, concatenated with the salt.</returns>
    public static string HashPassword(byte[] passwordBytes, byte[] saltBytes, byte[]? pepperBytes = null)
    {
        var saltAndPepper = pepperBytes is null ? new byte[saltBytes.Length] : 
            new byte[saltBytes.Length + pepperBytes.Length];
        
        Array.Copy(saltBytes, saltAndPepper, saltBytes.Length);
        if (pepperBytes is not null)
        {
            Array.Copy(pepperBytes, 0, saltAndPepper, saltBytes.Length, pepperBytes.Length);
        }
        
        var argon2Id = new Argon2id(passwordBytes);
        argon2Id.Iterations = 2;
        argon2Id.MemorySize = 8192;
        argon2Id.DegreeOfParallelism = 1;
        argon2Id.Salt = saltAndPepper;
        var digest = argon2Id.GetBytes(24);
        return Convert.ToBase64String(digest) + SaltDelimiter + Convert.ToBase64String(saltBytes);
    }
}
