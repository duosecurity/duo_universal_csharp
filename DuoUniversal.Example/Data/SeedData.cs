using System.Linq;

namespace DuoUniversal.Example.Data
{
    public static class SeedData
    {
        public static void Initialize(AppDbContext context)
        {
            context.Database.EnsureCreated();

            if (context.Users.Any())
            {
                return;   // DB has been seeded
            }

            context.Users.Add(new User
            {
                Username = "duouser",
                Password = "password123" // In production, hash this!
            });

            context.SaveChanges();
        }
    }
}
