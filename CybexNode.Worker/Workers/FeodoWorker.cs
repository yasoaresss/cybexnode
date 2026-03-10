using System.Net.Http.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class FeodoWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<FeodoWorker> _logger;

    public FeodoWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<FeodoWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("FeodoWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "FeodoWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        var apiBase = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var apiKey = _config["ApiKey"];

        var feodoClient = _httpClientFactory.CreateClient("Feodo");
        var response = await feodoClient.GetAsync(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("FeodoTracker API returned {StatusCode}", response.StatusCode);
            return;
        }

        var entries = await response.Content.ReadFromJsonAsync<List<FeodoEntry>>(cancellationToken: ct);
        if (entries is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", apiKey);

        int sent = 0;
        foreach (var entry in entries)
        {
            var dto = new ExternalIncidentDto(
                SourceIp: entry.IpAddress,
                AttackType: $"Malware C2 - {entry.Malware ?? "Unknown"}",
                Severity: "Critical",
                DataSource: "FeodoTracker",
                SourceCountry: entry.Country,
                DestinationPort: entry.Port,
                Protocol: "TCP",
                Description: $"FeodoTracker C2 server. Malware: {entry.Malware}. Status: {entry.Status}. First seen: {entry.FirstSeen}"
            );

            var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/incidents/external", dto, ct);
            if (postResp.IsSuccessStatusCode)
                sent++;
            else
                _logger.LogWarning("Failed to POST Feodo entry {Ip}: {Status}", entry.IpAddress, postResp.StatusCode);
        }

        _logger.LogInformation("FeodoWorker: sent {Count} C2 entries.", sent);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class FeodoEntry
    {
        [JsonPropertyName("ip_address")]
        public string IpAddress { get; set; } = string.Empty;

        [JsonPropertyName("port")]
        public int? Port { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("malware")]
        public string? Malware { get; set; }

        [JsonPropertyName("country")]
        public string? Country { get; set; }

        [JsonPropertyName("first_seen")]
        public string? FirstSeen { get; set; }
    }
}
