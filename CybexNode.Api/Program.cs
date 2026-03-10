using CybexNode.Api.Authentication;
using CybexNode.Api.Data;
using CybexNode.Api.Hubs;
using CybexNode.Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// ── Database ──────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<CybexDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ── Authentication (X-Api-Key) ────────────────────────────────────────────────
builder.Services
    .AddAuthentication(ApiKeyAuthHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthHandler>(ApiKeyAuthHandler.SchemeName, _ => { });

builder.Services.AddAuthorization();

// ── GeoIP ─────────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<GeoLocationService>();

// ── SignalR ───────────────────────────────────────────────────────────────────
builder.Services.AddSignalR();

// ── Controllers + Swagger ─────────────────────────────────────────────────────
builder.Services.AddControllers()
    .AddJsonOptions(o =>
    {
        o.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
        o.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        o.JsonSerializerOptions.PropertyNameCaseInsensitive = true; // accept both PascalCase (workers) and camelCase (frontend)
    });
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "CybexNode.Api", Version = "v1" });
    c.AddSecurityDefinition("ApiKey", new()
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Name = "X-Api-Key",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Description = "API key for honeypot sensors",
    });
    c.AddSecurityRequirement(new()
    {
        {
            new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "ApiKey" } },
            []
        }
    });
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("CybexNodePolicy", policy =>
    {
        policy.WithOrigins(
                  "http://localhost:3000",
                  "https://blue-field-0a275ef0f.6.azurestaticapps.net"
              )
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // necessário para SignalR
    });
});

var app = builder.Build();

app.UseWebSockets(); 

app.UseCors("CybexNodePolicy");

// ── Middleware ─────────────────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection(); // 

app.UseAuthentication();
app.UseAuthorization();

// ── Health endpoint ───────────────────────────────────────────────────────────
app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    timestamp = DateTime.UtcNow,
    service = "CybexNode.Api",
})).WithTags("Health").AllowAnonymous();

// ── Controllers ───────────────────────────────────────────────────────────────
app.MapControllers();

// ── SignalR Hub ───────────────────────────────────────────────────────────────
app.MapHub<IncidentHub>("/hubs/incidents")
 .AllowAnonymous();

// ── Auto-migrate on startup (dev convenience) ─────────────────────────────────
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<CybexDbContext>();
    db.Database.Migrate();
}

app.Run();
