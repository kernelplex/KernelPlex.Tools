using FluentAssertions;

namespace KernelPlex.Tools.Cryptography.Tests;

public class HashGeneratorTest
{

    private readonly string secret = "Hunter2";
    private readonly string badSecret = "Hunter3";
    private readonly byte[] _pepper;

    public HashGeneratorTest()
    {
        _pepper = HashGenerator.GenerateSpice();
    }

    [Fact]
    public void Verify_WithoutPepper_ShouldVerify()
    {
        var hashedSecret = HashGenerator.HashPassword(secret);

        HashGenerator.Verify(hashedSecret, secret).Should().BeTrue();
    }
    
    [Fact]
    public void Verify_WithPepper_ShouldVerify()
    {
        var hashedSecret = HashGenerator.HashPassword(secret, _pepper);

        HashGenerator.Verify(hashedSecret, secret, _pepper).Should().BeTrue();
    }
    
    [Fact]
    public void Verify_WithPepper_ShouldNOtVerifyIfSecretMismatched()
    {
        var hashedSecret = HashGenerator.HashPassword(secret, _pepper);

        HashGenerator.Verify(hashedSecret, badSecret, _pepper).Should().BeFalse();
    }


    [Fact]
    public void HashPassword_MultipleTimesWithSamePassword_GeneratesDifferentResults()
    {
        var firstHash = HashGenerator.HashPassword(secret);
        var secondHash = HashGenerator.HashPassword(secret);

        firstHash.Should().NotBe(secondHash);
    }
    
    [Fact]
    public void Verify_ShouldNotMatchWhenPepperIsMissing()
    {
        var hashedPassword = HashGenerator.HashPassword("Hunter2", _pepper);

        var result = HashGenerator.Verify(hashedPassword, "Hunter2");
        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_ShouldThrowIfBadHashPassed()
    {
        var badHash = "qpwoeiweporiuoqweiur";

        var act = () => HashGenerator.Verify(badHash, secret);

        act.Should().Throw<InvalidOperationException>();

    }
    
    [Fact]
    public void Verify_ShouldThrowIfSaltMissing()
    {
        var hashedPassword = HashGenerator.HashPassword("Hunter2", _pepper);
        var parts = hashedPassword.Split('$', 2);

        var act = () => HashGenerator.Verify(parts[0], "Hunter2");

        act.Should().Throw<InvalidOperationException>();
    }
}

