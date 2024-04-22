using Microsoft.EntityFrameworkCore;
using NetDevPack.Identity.Data;

namespace UserControl.Api.Authenticacao.Extensions
{
    public static class MigrationsExtensions
    {
        public static void ApplyMigrations(this IApplicationBuilder app)
        {
            using IServiceScope scope = app.ApplicationServices.CreateScope();

            using NetDevPackAppDbContext dbContext= scope.ServiceProvider.GetRequiredService<NetDevPackAppDbContext>();

            dbContext.Database.Migrate();
        }
    }
}
