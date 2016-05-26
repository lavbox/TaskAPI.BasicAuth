using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TaskAPI.Models
{
    public interface ITaskDataProvider
    {
        IEnumerable<User> Users { get; set; }
        IEnumerable<Task> Tasks { get; set; }
        IEnumerable<TaskList> TaskLists { get; set; }
    }
}
