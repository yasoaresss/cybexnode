using CybexNode.Worker.Workers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

builder.Services.AddHostedService<OtxWorker>();
builder.Services.AddHostedService<AbuseIpDbWorker>();
builder.Services.AddHostedService<FeodoWorker>();
builder.Services.AddHostedService<CisaWorker>();
builder.Services.AddHostedService<DShieldWorker>();
builder.Services.AddHostedService<HoneyDbWorker>();
builder.Services.AddHostedService<GreyNoiseWorker>();

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new { status = "running", service = "CybexNode.Worker" }));

app.Run();
