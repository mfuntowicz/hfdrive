using Xunit;

namespace HfDrive.Protocol.Tests;

public sealed class LoginRedactionTests
{
    [Fact]
    public void Transient_Login_Instructions_Are_Not_Record_Debug_Output()
    {
        var result = new StartLoginResult
        {
            SessionId = Guid.Parse("12345678-1234-4234-8234-123456789abc"),
            AuthorizationUrl = "https://huggingface.co/oauth/authorize?state=MARKER-STATE",
            UserCode = "MARKER-USER-CODE",
            VerificationUri = "https://huggingface.co/oauth/device?user_code=MARKER-CODE",
            ExpiresAt = "2026-11-13T18:00:00Z",
        };
        Assert.DoesNotContain("MARKER", result.ToString(), StringComparison.Ordinal);
    }
}
