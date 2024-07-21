using System.Security.Claims;
using System.Text;
using AuthApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Read JWT key from file
var jwtKey = File.ReadAllText("jwtkey.txt").Trim();
builder.Configuration["Jwt:Key"] = jwtKey;

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = "CustomScheme";
        options.DefaultChallengeScheme = "CustomScheme";
    })
    .AddScheme<AuthenticationSchemeOptions, CustomJwtAuthenticationHandler>("CustomScheme", options => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireClaim(ClaimTypes.Role, "admin"));
});

// Configure DbContext for user management
builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add controllers
builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add CORS policy
app.UseCors(builder => 
{ 
    builder.WithOrigins("http://localhost:4200", "http://localhost:5001")
        .AllowAnyHeader()
        .WithMethods("DELETE", "PUT", "POST", "GET")
        .AllowCredentials();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
