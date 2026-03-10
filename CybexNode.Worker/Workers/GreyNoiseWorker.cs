using System.Net.Http.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class GreyNoiseWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<GreyNoiseWorker> _logger;

    public GreyNoiseWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<GreyNoiseWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("GreyNoiseWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GreyNoiseWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        var gnKey   = _config["ExternalApis:GreyNoiseApiKey"];
        var apiBase = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var apiKey  = _config["ApiKey"];

        var gnClient = _httpClientFactory.CreateClient("GreyNoise");
        gnClient.DefaultRequestHeaders.TryAddWithoutValidation("key", gnKey);

        var response = await gnClient.GetAsync(
            "https://api.greynoise.io/v2/experimental/gnql/stats?query=last_seen:1d&count=100", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("GreyNoise API returned {StatusCode}", response.StatusCode);
            return;
        }

        var root = await response.Content.ReadFromJsonAsync<GreyNoiseStatsResponse>(cancellationToken: ct);
        if (root?.Ips is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", apiKey);

        int sent = 0;
        foreach (var entry in root.Ips)
        {
            if (string.IsNullOrWhiteSpace(entry.Ip)) continue;

            var severity = entry.Classification == "malicious" ? "High" : "Medium";
            var description = entry.Tags is { Count: > 0 }
                ? string.Join(", ", entry.Tags)
                : "Internet scanner";

            var dto = new ExternalIncidentDto(
                SourceIp:        entry.Ip,
                AttackType:      $"GreyNoise — {entry.Classification}",
                Severity:        severity,
                DataSource:      "GreyNoise",
                SourceCountry:   entry.Metadata?.Country,
                DestinationPort: null,
                Protocol:        entry.Metadata?.Os,
                Description:     description
            );

            var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/incidents/external", dto, ct);
            if (postResp.IsSuccessStatusCode)
                sent++;
            else
                _logger.LogWarning("Failed to POST GreyNoise entry {Ip}: {Status}", entry.Ip, postResp.StatusCode);
        }

        _logger.LogInformation("GreyNoiseWorker: sent {Count} entries.", sent);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class GreyNoiseStatsResponse
    {
        [JsonPropertyName("data")]
        public List<GreyNoiseEntry>? Ips { get; set; }
    }

    private sealed class GreyNoiseEntry
    {
        [JsonPropertyName("ip")]
        public string Ip { get; set; } = string.Empty;

        [JsonPropertyName("classification")]
        public string? Classification { get; set; }

        [JsonPropertyName("tags")]
        public List<string>? Tags { get; set; }

        [JsonPropertyName("metadata")]
        public GreyNoiseMetadata? Metadata { get; set; }
    }

    private sealed class GreyNoiseMetadata
    {
        [JsonPropertyName("country")]
        public string? Country { get; set; }

        [JsonPropertyName("os")]
        public string? Os { get; set; }
    }
}
