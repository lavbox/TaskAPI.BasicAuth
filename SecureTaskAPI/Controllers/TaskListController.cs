using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Data.Entity;
using TaskAPI.Models;
using System.Web.Http;
using SecureTaskAPI.Filters;

namespace TaskAPI.Controllers
{
    [RoutePrefix("api/tasklist")]
    [BasicAuthenticationFilter]
    [Authorize]
    public class TaskListController : ApiController
    {
        private readonly TaskContext _context;
        public TaskListController()
        {
            _context = new TaskContext();
        }

        // GET: api/tasklist/8ab4fcbd993f49ce8a21103c713bf47a
        [HttpGet()]
        [Route("{userId}")]
        public async Task<IEnumerable<TaskList>> GetAll(string userId)
        {
            return await _context.TaskLists.Where(p => p.UserId == userId && p.IsDeleted != true).ToListAsync();
        }


        // POST api/tasklist
        [HttpPost]
        [Route("")]
        public async Task<IHttpActionResult> Post([FromBody]CreateTaskListRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            else
            {
                var userExists = await _context.Users.AnyAsync(i => i.UserId == request.UserId);
                if (userExists)
                {
                    var itemExists = await _context.TaskLists.AnyAsync(i => i.Title == request.TaskListTitle && i.UserId == request.UserId);
                    if (itemExists)
                    {
                        return BadRequest();
                    }
                    TaskList item = new Models.TaskList();
                    item.TaskListId = Guid.NewGuid().ToString().Replace("-", "");
                    item.UserId = request.UserId;
                    item.CreatedOnUtc = DateTime.UtcNow;
                    item.UpdatedOnUtc = DateTime.UtcNow;
                    item.Title = request.TaskListTitle;
                    _context.TaskLists.Add(item);
                    await _context.SaveChangesAsync();
                    System.Web.HttpContext.Current.Response.StatusCode = 201;
                    return Ok();
                }
                else
                {
                    return BadRequest();
                }
            }
        }

        // DELETE api/tasklist/5ab4fcbd993f49ce8a21103c713bf47a
        [HttpDelete]
        [Route("")]
        public async Task<IHttpActionResult> Delete([FromBody]DeleteTaskListRequest request)
        {
            var item = await _context.TaskLists.FirstOrDefaultAsync(x => x.TaskListId == request.TaskListId 
            && x.UserId == request.UserId && x.IsDeleted != true);
            if (item == null)
            {
                return NotFound();
            }
            item.IsDeleted = true;
            item.UpdatedOnUtc = DateTime.UtcNow;
            _context.Entry(item).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return StatusCode(System.Net.HttpStatusCode.NoContent); // 201 No Content
        }
    }
}
