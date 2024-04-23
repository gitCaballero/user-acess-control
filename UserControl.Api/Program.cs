using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using NetDevPack.Identity.Jwt;
using System.Reflection;
using UserControl.Api.Authenticacao.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Connection"),
    b => b.MigrationsAssembly("UserControl.Api.Authenticacao")));

builder.Services.AddJwtConfiguration(builder.Configuration, appJwtSettingsKey: "AppSettings");

builder.Services.AddIdentityConfiguration();


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
var security = new OpenApiSecurityRequirement()
        {
            { new OpenApiSecurityScheme(){ Scheme="Bearer"}, new string[] { } }
        };


builder.Services.AddSwaggerGen
  (
    c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo()
        {
            Title = "Api Authentication for Motorcycle Rental and Delivery",
            Version = "v1",
            Contact = new OpenApiContact() { Name = "David", Email = "caballero.david2011@gmail.com" }
        });
        c.IncludeXmlComments(xmlPath);
        c.AddSecurityDefinition(
       "Bearer",
       new OpenApiSecurityScheme
       {
           In = ParameterLocation.Header,
           Description = "Copy 'Bearer ' + token'",
           Name = "Authorization",
           Type = SecuritySchemeType.ApiKey
       });

        c.AddSecurityRequirement(security);
    });

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseDeveloperExceptionPage();

app.UseSwagger();

app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
    });
app.ApplyMigrations();

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthConfiguration();

app.MapControllers();

app.Run();
