using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TaskAPI.Models
{
    /// <summary>
    /// Request to create a task on a task list
    /// </summary>
    public class CreateTaskRequest
    {
        /// <summary>
        /// Task List Id
        /// </summary>
        public string TaskListId { get; set; }
        
        /// <summary>
        /// Task List Description
        /// </summary>
        public string TaskTitle { get; set; }
    }
}
