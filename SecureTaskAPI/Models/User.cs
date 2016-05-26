using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TaskAPI.Models
{
    public class User
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
        /// User email address
        /// </summary>
        public string EmailAddress { get; set; }

        /// <summary>
        /// User created on date
        /// </summary>
        public DateTime CreatedOnUtc { get; set; }

        /// <summary>
        /// User updated on date
        /// </summary>
        public DateTime UpdatedOnUtc { get; set; }

        /// <summary>
        /// True if user is deleted
        /// </summary>
        public bool? IsDeleted { get; set; }

        /// <summary>
        /// True if user is active
        /// </summary>
        public bool? IsActive { get; set; }
    }
}
