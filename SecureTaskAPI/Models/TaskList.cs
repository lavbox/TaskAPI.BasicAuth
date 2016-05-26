using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TaskAPI.Models
{
    public class TaskList
    {
        /// <summary>
        /// Identity
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// User unique Id
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// Task list unique Id
        /// </summary>
        public string TaskListId { get; set; }

        /// <summary>
        /// Task list title
        /// </summary>
        public string Title { get; set; }

        /// <summary>
        /// Task list created on date
        /// </summary>
        public DateTime CreatedOnUtc { get; set; }

        /// <summary>
        /// Task list updated on date
        /// </summary>
        public DateTime UpdatedOnUtc { get; set; }

        /// <summary>
        /// True list if task is deleted
        /// </summary>
        public bool? IsDeleted { get; set; }

        /// <summary>
        /// True list if task is active
        /// </summary>
        public bool? IsActive { get; set; }
    }
}
