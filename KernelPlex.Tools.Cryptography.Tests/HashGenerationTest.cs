using FluentAssertions;

namespace KernelPlex.Tools.Cryptography.Tests;

public class HashGenerationTest
{

    private readonly string secret = "Hunter2";
    private readonly string badSecret = "Hunter3";
    private readonly byte[] _pepper;

    public HashGenerationTest()
    {
        _pepper = HashGeneration.GenerateSpice();
    }

    [Fact]
    public void Verify_WithoutPepper_ShouldVerify()
    {
        var hashedSecret = HashGeneration.HashPassword(secret);

        HashGeneration.Verify(hashedSecret, secret).Should().BeTrue();
    }
    
    [Fact]
    public void Verify_WithPepper_ShouldVerify()
    {
        var hashedSecret = HashGeneration.HashPassword(secret, _pepper);

        HashGeneration.Verify(hashedSecret, secret, _pepper).Should().BeTrue();
    }
    
    [Fact]
    public void Verify_WithPepper_ShouldNOtVerifyIfSecretMismatched()
    {
        var hashedSecret = HashGeneration.HashPassword(secret, _pepper);

        HashGeneration.Verify(hashedSecret, badSecret, _pepper).Should().BeFalse();
    }


    [Fact]
    public void HashPassword_MultipleTimesWithSamePassword_GeneratesDifferentResults()
    {
        var firstHash = HashGeneration.HashPassword(secret);
        var secondHash = HashGeneration.HashPassword(secret);

        firstHash.Should().NotBe(secondHash);
    }
    
    [Fact]
    public void Verify_ShouldNotMatchWhenPepperIsMissing()
    {
        var hashedPassword = HashGeneration.HashPassword("Hunter2", _pepper);

        var result = HashGeneration.Verify(hashedPassword, "Hunter2");
        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_ShouldThrowIfBadHashPassed()
    {
        var badHash = "qpwoeiweporiuoqweiur";

        var act = () => HashGeneration.Verify(badHash, secret);

        act.Should().Throw<InvalidOperationException>();

    }
    
    [Fact]
    public void Verify_ShouldThrowIfSaltMissing()
    {
        var hashedPassword = HashGeneration.HashPassword("Hunter2", _pepper);
        var parts = hashedPassword.Split(HashGeneration.SaltDelimiter, 2);

        var act = () => HashGeneration.Verify(parts[0], "Hunter2");

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Verify_ShouldWorkWithBase64_Pepper()
    {
        var pepper64 = HashGeneration.GenerateBase64Spice();
        var hashedPassword = HashGeneration.HashPassword(this.secret, pepper64);

        var result = HashGeneration.Verify(hashedPassword, secret, pepper64);

        result.Should().BeTrue();
    }
    
    [Fact]
    public void Verify_ShouldFailWhenNoPepperProvided()
    {
        var pepper64 = HashGeneration.GenerateBase64Spice();
        var hashedPassword = HashGeneration.HashPassword(this.secret, pepper64);

        var result = HashGeneration.Verify(hashedPassword, secret);

        result.Should().BeFalse();
    }
}

