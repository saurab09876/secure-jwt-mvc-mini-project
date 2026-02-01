using SecureJwtMiniProject.Models;

public interface ITokenService
{
    string GenerateAccessToken(User user);
}
