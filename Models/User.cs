using Microsoft.EntityFrameworkCore;

namespace AuthApi;

public class User
{
    public int Id { get; set; }
    public string username { get; set; }
    public string password_Hash { get; set; }
    public string role { get; set; } //Valid roles are "admin" and "employee"
}