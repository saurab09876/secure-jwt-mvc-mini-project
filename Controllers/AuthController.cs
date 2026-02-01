using Azure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureJwtMiniProject.Data;
using SecureJwtMiniProject.Models;

public class AuthController : Controller
{
    private readonly AppDbContext _db;
    private readonly ITokenService _tokenService;

    public AuthController(AppDbContext db, ITokenService tokenService)
    {
        _db = db;
        _tokenService = tokenService;
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Login(LoginModel model)
    {
        var user = _db.Users.FirstOrDefault(x => x.Username == model.Username);
        if (user == null)
            return Unauthorized();

        var hasher = new PasswordHasher<User>();
        var result = hasher.VerifyHashedPassword(
            user, user.PasswordHash, model.Password);

        if (result == PasswordVerificationResult.Failed)
            return Unauthorized();

        // 🔐 JWT generate
        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // 🔹 DB me save
        _db.RefreshTokens.Add(new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiryDate = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        });
        _db.SaveChanges();

        // 🔹 Cookies me store
        Response.Cookies.Append("accessToken", accessToken,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Strict
            });

        Response.Cookies.Append("refreshToken", refreshToken,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Strict
            });


        return RedirectToAction("Dashboard", "Home");
        
    }

    [HttpPost]
    public IActionResult Refresh()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (refreshToken == null)
            return Unauthorized();

        var storedToken = _db.RefreshTokens
            .Include(x => x.User)
            .FirstOrDefault(x =>
                x.Token == refreshToken &&
                !x.IsRevoked &&
                x.ExpiryDate > DateTime.UtcNow);

        if (storedToken == null)
            return Unauthorized();

        // 🔁 ROTATION
        storedToken.IsRevoked = true;

        var newAccessToken =
            _tokenService.GenerateAccessToken(storedToken.User);
        var newRefreshToken =
            _tokenService.GenerateRefreshToken();

        _db.RefreshTokens.Add(new RefreshToken
        {
            Token = newRefreshToken,
            UserId = storedToken.UserId,
            ExpiryDate = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        });

        _db.SaveChanges();

        Response.Cookies.Append("accessToken", newAccessToken,
            new CookieOptions { HttpOnly = true, Secure = false });

        Response.Cookies.Append("refreshToken", newRefreshToken,
            new CookieOptions { HttpOnly = true, Secure = false });

        return Ok();
    }

}
