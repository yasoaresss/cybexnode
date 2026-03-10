using System.Net.Http.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class DShieldWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<DShieldWorker> _logger;

    public DShieldWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<DShieldWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("DShieldWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DShieldWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        var dshieldKey = _config["ExternalApis:DShieldApiKey"];
        var apiBase    = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var apiKey     = _config["ApiKey"];

        var dshieldClient = _httpClientFactory.CreateClient("DShield");
        dshieldClient.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $"Bearer {dshieldKey}");

        var response = await dshieldClient.GetAsync(
            "https://isc.sans.edu/api/topattackers?json", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("DShield API returned {StatusCode}", response.StatusCode);
            return;
        }

        var root = await response.Content.ReadFromJsonAsync<List<DShieldEntry>>(cancellationToken: ct);
        if (root is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", apiKey);

        int sent = 0;
        foreach (var entry in root)
        {
            if (string.IsNullOrWhiteSpace(entry.IpAddr)) continue;

            var dto = new ExternalIncidentDto(
                SourceIp:        entry.IpAddr,
                AttackType:      "Port Scan — DShield",
                Severity:        "Medium",
                DataSource:      "DShield",
                SourceCountry:   entry.Country,
                DestinationPort: null,
                Protocol:        "TCP",
                Description:     $"Top attacker — {entry.Attacks} ataques reportados"
            );

            var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/incidents/external", dto, ct);
            if (postResp.IsSuccessStatusCode)
                sent++;
            else
                _logger.LogWarning("Failed to POST DShield entry {Ip}: {Status}", entry.IpAddr, postResp.StatusCode);
        }

        _logger.LogInformation("DShieldWorker: sent {Count} entries.", sent);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class DShieldEntry
    {
        [JsonPropertyName("ipaddr")]
        public string IpAddr { get; set; } = string.Empty;

        [JsonPropertyName("attacks")]
        public int Attacks { get; set; }

        [JsonPropertyName("country")]
        public string? Country { get; set; }
    }
}
