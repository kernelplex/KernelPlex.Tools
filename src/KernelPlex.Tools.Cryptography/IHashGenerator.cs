namespace KernelPlex.Tools.Cryptography;

/// <summary>
/// Provides methods for generating and verifying hashed password.
/// </summary>
public interface IHashGenerator
{
    /// <summary>
    /// Generates a hashed password using the provided string password.
    /// </summary>
    /// <param name="password">The password to be hashed.</param>
    /// <returns>A string representing the hashed password.</returns>
    public string HashPassword(string password);

    /// <summary>
    /// Verifies if a given password matches a hashed password.
    /// </summary>
    /// <param name="password">The password to be verified.</param>
    /// <param name="hashedPassword">The hashed password to compare against.</param>
    /// <returns>
    /// True if the password matches the hashed password, false otherwise.
    /// </returns>
    public string Verify(string password, string hashedPassword);
}