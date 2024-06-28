using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.VisualStudio.TestPlatform.CommunicationUtilities.Serialization;

namespace KernelPlex.Tools.Cryptography.Tests;


public class EncryptionTest
{
    private readonly byte[] _key;
    private readonly byte[] _badKey;

    private readonly string _secret =
        "User ID=root;Password=myPassword;Host=localhost;Port=5432;Database=myDataBase;Pooling=true;Min Pool Size=0;Max Pool Size=100;Connection Lifetime=0;";

    public EncryptionTest()
    {
        _key = HashGenerator.GenerateSpice();
        _badKey = HashGenerator.GenerateSpice();
        
        // Just in case we get (un)lucky.
        Assert.NotEqual(_key, _badKey);
    }
    
    
    [Fact]
    public void DecryptString_ShouldMatch_EncryptedString()
    {
        var encrypted = Encryption.EncryptString(_secret, _key);

        var decrypted = Encryption.DecryptString(encrypted, _key);
decrypted.Should().Be(decrypted);
    }
    
    [Fact]
    public void DecryptString_WithBadKey_ShouldNotMatch()
    {
        var encrypted = Encryption.EncryptString(_secret, _key);

        var act = () => Encryption.DecryptString(encrypted, _badKey);

        act.Should().Throw < CryptographicException>();
    }
    
    [Fact]
    public void Encrypt_MultipleTimesWithSameSecretAndKey_ShouldGenerateDifferentResults()
    {
        var encrypted1 = Encryption.EncryptString(_secret, _key);
        var encrypted2 = Encryption.EncryptString(_secret, _key);

        encrypted1.Should().NotBe(encrypted2);
    }

}