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
    [RoutePrefix("api/task")]
    [BasicAuthenticationFilter]
    //[CertificateAuthenticationFilter]
    [Authorize]
    public class TaskController : ApiController
    {
        private readonly TaskContext _context;
        public TaskController()
        {
            _context = new TaskContext();
        }

        // GET: api/task/2ab4fcbd993f49ce8a21103c713bf47a
        [HttpGet()]
        [Route("{taskListId}")]
        public async Task<IEnumerable<Models.Task>> GetAll(string taskListId)
        {
            return await _context.Tasks.Where(p => p.TaskListId == taskListId && p.IsDeleted != true).ToListAsync();
        }


        // POST api/task
        [HttpPost]
        [Route("")]
        public async Task<IHttpActionResult> Post([FromBody]CreateTaskRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            else
            {
                var itemExists = await _context.Tasks.AnyAsync(i => i.Title == request.TaskTitle && i.TaskListId == request.TaskListId && i.IsDeleted != true);
                if (itemExists)
                {
                    return BadRequest();
                }
                Models.Task item = new Models.Task();
                item.TaskListId = request.TaskListId;
                item.TaskId = Guid.NewGuid().ToString().Replace("-", ""); ;
                item.CreatedOnUtc = DateTime.UtcNow;
                item.UpdatedOnUtc = DateTime.UtcNow;
                item.Title = request.TaskTitle;
                _context.Tasks.Add(item);
                await _context.SaveChangesAsync();

                var tasks = await _context.Tasks.Where(i => i.TaskListId == request.TaskListId && i.IsDeleted != true).Select(p=>new { Title = p.Title }).ToListAsync();
                var getTaskList = await _context.TaskLists.Where(i => i.TaskListId == request.TaskListId).SingleOrDefaultAsync();
                var user = await _context.Users.Where(u => u.UserId == getTaskList.UserId).SingleOrDefaultAsync();
                return Json(new {User=user.EmailAddress,Tasks = tasks,TaskList=getTaskList.Title });
            }
        }
        
        // PUT api/task
        [HttpPut]
        [Route("")]
        public async Task<IHttpActionResult> Put([FromBody]UpdateTaskRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }
            else
            {
                var itemExists = await _context.Tasks.SingleOrDefaultAsync(i => i.TaskId == request.TaskId && i.TaskListId == request.TaskListId && i.IsDeleted != true);
                if (itemExists != null)
                {
                    // parse the updated properties
                    foreach (var item in request.Data)
                    {
                        switch (item.Key)
                        {
                            case TaskPropertyEnum.IsCompleted:
                                itemExists.IsCompleted = bool.Parse(item.Value);
                                break;
                            case TaskPropertyEnum.CompletedOn:
                                itemExists.CompletedOnUtc = DateTime.Parse(item.Value);
                                break;
                            case TaskPropertyEnum.DueOn:
                                itemExists.DueOnUtc = DateTime.Parse(item.Value);
                                break;
                            case TaskPropertyEnum.IsActive:
                                itemExists.IsActive = bool.Parse(item.Value);
                                break;
                            case TaskPropertyEnum.Title:
                                itemExists.Title = item.Value;
                                break;
                            default:
                                break;
                        }
                    }
                    _context.Entry(itemExists).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                    System.Web.HttpContext.Current.Response.StatusCode = 201;
                    return Ok();
                }
                return BadRequest("Record not found. Make sure it exists");
            }
        }

        // DELETE api/task/1ab4fcbd993f49ce8a21103c713bf47a
        [HttpDelete]
        [Route("")]
        public async Task<IHttpActionResult> Delete([FromBody]DeleteTaskRequest request)
        {
            var item = await _context.Tasks.FirstOrDefaultAsync(x => x.TaskId == request.TaskId && x.TaskListId == request.TaskListId  && x.IsDeleted != true);
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
