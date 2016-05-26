using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Data.Entity;
using TaskAPI.Models;
using System.Security.Claims;
using System.Web.Http;
using SecureTaskAPI.Filters;

namespace TaskAPI.Controllers
{
    [RoutePrefix("api/user")]
    [BasicAuthenticationFilter]
    [Authorize]
    public class UserController : ApiController
    {
        private readonly TaskContext _context;
        public UserController()
        {
            _context = new TaskContext();
        }

        // GET: api/user
        [HttpGet]
        [Route("")]
        public async Task<IEnumerable<User>> GetAll()
        {
            return await _context.Users.Where(p => p.IsDeleted != true).ToListAsync();
        }

        // GET api/user/sample@mail.com
        [HttpGet]
        [Route("{value}")]
        public async Task<User> Get(string value)
        {
            var item = await _context.Users.FirstOrDefaultAsync(x => x.EmailAddress == value && x.IsDeleted != true);
            return item;
        }


        [HttpPost]
        [Route("")]
        // POST api/user
        public async Task<IHttpActionResult> Post([FromBody]CreateUserRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            else
            {
                var itemExists = await _context.Users.AnyAsync(i => i.EmailAddress == request.EmailAddress && i.IsDeleted != true);
                if (itemExists)
                {
                    return BadRequest();
                }
                User item = new Models.User();
                item.UserId = Guid.NewGuid().ToString().Replace("-", "");
                item.CreatedOnUtc = DateTime.UtcNow;
                item.UpdatedOnUtc = DateTime.UtcNow;
                item.EmailAddress = request.EmailAddress;
                _context.Users.Add(item);
                await _context.SaveChangesAsync();
                System.Web.HttpContext.Current.Response.StatusCode = 201;
                return Ok();
            }
        }

        // DELETE api/user/3ab4fcbd993f49ce8a21103c713bf47a
        [HttpDelete]
        [Route("")]
        public async Task<IHttpActionResult> Delete([FromBody]DeleteUserRequest request)
        {
            var item = await _context.Users.FirstOrDefaultAsync(x => x.UserId == request.UserId && x.IsDeleted != true);
            if (item == null)
            {
                return NotFound();
            }
            item.IsDeleted = true;
            item.UpdatedOnUtc = DateTime.UtcNow;
            _context.Entry(item).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return StatusCode(System.Net.HttpStatusCode.NoContent); // 204 No Content
        }
    }



}
