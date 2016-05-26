using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TaskAPI.Models
{
    public class UpdateTaskRequest
    {
        public string TaskListId { get; set; }

        public string TaskId { get; set; }

        public KeyValuePair[] Data { get; set; }
    }
}
