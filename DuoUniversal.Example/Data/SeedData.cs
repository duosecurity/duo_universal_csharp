using System.Linq;

namespace DuoUniversal.Example.Data
{
    public static class SeedData
    {
        public static void Initialize(AppDbContext context)
        {
            context.Database.EnsureCreated();

            if (!context.Users.Any(u => u.Username == "duouser"))
            {
                context.Users.Add(new User
                {
                    Username = "duouser",
                    Password = "password123"
                });
            }

            if (!context.Users.Any(u => u.Username == "Desktop_versus"))
            {
                context.Users.Add(new User
                {
                    Username = "Desktop_versus",
                    Password = "password123"
                });
            }

            context.SaveChanges();
        }
    }
}
