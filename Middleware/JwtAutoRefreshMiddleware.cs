using Microsoft.EntityFrameworkCore;
using SecureJwtMiniProject.Data;
using System.IdentityModel.Tokens.Jwt;

public class JwtAutoRefreshMiddleware
{
    private readonly RequestDelegate _next;

    public JwtAutoRefreshMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(
        HttpContext context,
        AppDbContext db,
        ITokenService tokenService)
    {
        var accessToken = context.Request.Cookies["accessToken"];
        if (!string.IsNullOrEmpty(accessToken))
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(accessToken);

            if (jwt.ValidTo < DateTime.UtcNow)
            {
                // 🔁 call refresh silently
                context.Request.Method = "POST";
                context.Request.Path = "/Auth/Refresh";
            }
        }

        await _next(context);
    }
}
