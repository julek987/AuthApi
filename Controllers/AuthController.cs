using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Controllers;

[ApiController]
[Route("[controller]")]
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
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _context.users.SingleOrDefaultAsync(u => u.username == model.Username);
        if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.password_Hash))
        {
            return Unauthorized();
        }

        var token = GenerateJwtToken(user);
        return Ok(new { token });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        // Check if the role is valid
        var validRoles = new[] { "admin", "employee" };
        if (!validRoles.Contains(model.Role.ToLower()))
        {
            return BadRequest("Invalid role");
        }

        var userExists = await _context.users.AnyAsync(u => u.username == model.Username);
        if (userExists)
        {
            return BadRequest("User already exists");
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

        return Ok("User registered successfully");
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
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

