using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly UserDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthController(UserDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _context.users.SingleOrDefaultAsync(u => u.username == model.Username);
        if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.password_Hash))
        {
            return Unauthorized();
        }

        var token = GenerateJwtToken(user);
    
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Set to true if using HTTPS
            SameSite = SameSiteMode.Strict, // Allow cross-site cookies
            Expires = DateTime.UtcNow.AddMinutes(60) // Cookie expiration
        };
    
        Response.Cookies.Append("token", token, cookieOptions);

        // Return response with message and role
        return Ok(new { message = "Login successful, cookie set", user.role });
    }


    [HttpPost("register")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        // Check if the role is valid
        var validRoles = new[] { "admin", "employee" };
        if (!validRoles.Contains(model.Role.ToLower()))
        {
            return BadRequest(new { message = "Invalid role" });
        }

        var userExists = await _context.users.AnyAsync(u => u.username == model.Username);
        if (userExists)
        {
            return BadRequest(new { message = "User already exists" });
        }

        // Automatically generates a salt and hashes the password
        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);

        var user = new User
        {
            username = model.Username,
            password_Hash = hashedPassword,
            role = model.Role
        };

        _context.users.Add(user);
        await _context.SaveChangesAsync();

        return Ok(new { message = "User registered successfully" });
    }


    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, user.role)
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(60),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    [HttpPost("validate-token")]
    public IActionResult ValidateToken()
    {
        var valid = true;
        return Ok(new { valid });
    }

}


