using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TaskAPI.Models
{

    public class DeleteTaskListRequest
    {
        public string UserId { get; set; }
        public string TaskListId { get; set; }
    }
}
