using FluentAssertions;

namespace KernelPlex.Tools.Cryptography.Tests;

public class HashGeneratorTest
{
    private readonly string _secret = "Hunter2";
    private readonly string _badSecret = "Hunter3";
    private readonly string _pepper = "+Z3mn111bReUfxryxsu9NzQplVOzydDYOHcuH1rUa0I=";

    private HashGenerator iut;

    public HashGeneratorTest()
    {
        iut = new HashGenerator(_pepper);
    }

    [Fact]
    public void HashPassword_ShouldGenerateDifferentHashesForTheSameSecret()
    {
        var firstHash = iut.HashPassword(_secret);
        var secondHash = iut.HashPassword(_secret);

        firstHash.Should().NotBe(secondHash);
    }
    
    [Fact]
    public void Verify_ShouldReturnTrueIfSecretsMatch()
    {
        var hash = iut.HashPassword(_secret);
        var verified = iut.verify(_secret, hash);
        verified.Should().BeTrue();
    }
    
    [Fact]
    public void Verify_ShouldShouldReturnFalseIfSecretsDoNotMatch()
    {
        var hash = iut.HashPassword(_secret);
        var verified = iut.verify(_badSecret, hash);
        verified.Should().BeFalse();
    }
}