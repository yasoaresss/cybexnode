using System.Net.Http.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class HoneyDbWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<HoneyDbWorker> _logger;

    public HoneyDbWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<HoneyDbWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("HoneyDbWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HoneyDbWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        var apiId  = _config["ExternalApis:HoneyDbApiId"];
        var apiKey = _config["ExternalApis:HoneyDbApiKey"];
        var apiBase     = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var internalKey = _config["ApiKey"];

        var honeyClient = _httpClientFactory.CreateClient("HoneyDB");
        honeyClient.DefaultRequestHeaders.TryAddWithoutValidation("X-HoneyDb-ApiId",  apiId);
        honeyClient.DefaultRequestHeaders.TryAddWithoutValidation("X-HoneyDb-ApiKey", apiKey);

        var response = await honeyClient.GetAsync(
            "https://honeydb.io/api/sensor-data/today", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("HoneyDB API returned {StatusCode}", response.StatusCode);
            return;
        }

        var root = await response.Content.ReadFromJsonAsync<List<HoneyDbEntry>>(cancellationToken: ct);
        if (root is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", internalKey);

        int sent = 0;
        foreach (var entry in root)
        {
            if (string.IsNullOrWhiteSpace(entry.RemoteHost)) continue;

            var dto = new ExternalIncidentDto(
                SourceIp:        entry.RemoteHost,
                AttackType:      $"HoneyDB — {entry.Service}",
                Severity:        "Medium",
                DataSource:      "HoneyDB",
                SourceCountry:   entry.Country,
                DestinationPort: entry.RemotePort,
                Protocol:        entry.Service,
                Description:     $"Honeypot sensor hit — {entry.Service}"
            );

            var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/incidents/external", dto, ct);
            if (postResp.IsSuccessStatusCode)
                sent++;
            else
                _logger.LogWarning("Failed to POST HoneyDB entry {Ip}: {Status}", entry.RemoteHost, postResp.StatusCode);
        }

        _logger.LogInformation("HoneyDbWorker: sent {Count} entries.", sent);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class HoneyDbEntry
    {
        [JsonPropertyName("remote_host")]
        public string RemoteHost { get; set; } = string.Empty;

        [JsonPropertyName("remote_port")]
        public int? RemotePort { get; set; }

        [JsonPropertyName("service")]
        public string? Service { get; set; }

        [JsonPropertyName("country")]
        public string? Country { get; set; }
    }
}
