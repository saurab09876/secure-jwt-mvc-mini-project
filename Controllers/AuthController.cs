using Azure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
        var token = _tokenService.GenerateAccessToken(user);

        // 🍪 Cookie me store
        Response.Cookies.Append("accessToken", token,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = false, // prod me true
                SameSite = SameSiteMode.Strict
            });

        return RedirectToAction("Dashboard", "Home");
    }
}
