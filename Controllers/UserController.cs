using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly UserDbContext _context;

        public UserController(UserDbContext context)
        {
            _context = context;
        }

        // GET: api/user
        [HttpGet]
        [Authorize(Policy = "AdminOnly")]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            return await _context.users.ToListAsync();
        }

        // GET: api/user/{id}
        [HttpGet("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            var user = await _context.users.FindAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }
        
        // DELETE: api/user/delete/{id}
        [HttpDelete("delete/{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            // Find the user by ID
            var user = await _context.users.FindAsync(id); // Ensure 'Users' is capitalized

            if (user == null)
            {
                return NotFound(); // Return 404 if the user is not found
            }

            // Remove the user
            _context.users.Remove(user); // Ensure 'Users' is capitalized

            // Save changes to the database
            await _context.SaveChangesAsync();

            // Return a successful response
            return NoContent(); // Return 204 No Content on successful deletion
        }

    }
}