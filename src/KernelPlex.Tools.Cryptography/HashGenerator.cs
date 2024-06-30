namespace KernelPlex.Tools.Cryptography;

public class HashGenerator
{
    #region Fields

    private readonly byte[]? _pepperBytes;

    #endregion

    #region Constructors/Destructors
    
    public HashGenerator(byte[]? pepperBytes = null)
    {
        _pepperBytes = pepperBytes;
    }

    public HashGenerator(string base64Pepper): this(Convert.FromBase64String(base64Pepper))
    {
    }

    #endregion

    #region Methods

    public string HashPassword(string password)
    {
        return HashGeneration.HashPassword(password, _pepperBytes);
    }

    public bool verify(string password, string hashedPassword)
    {
        return HashGeneration.Verify(hashedPassword, password, _pepperBytes);
    }

    #endregion
}