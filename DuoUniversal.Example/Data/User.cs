using System.ComponentModel.DataAnnotations;

namespace DuoUniversal.Example.Data
{
    public class User
    {
        public int Id { get; set; }

        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; } // Storing plain text/simple hash for demo purposes
    }
}
