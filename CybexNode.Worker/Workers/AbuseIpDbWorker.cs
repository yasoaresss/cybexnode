using System.Net.Http.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class AbuseIpDbWorker : BackgroundService
{
    private static readonly TimeSpan Interval      = TimeSpan.FromHours(24);
    private static readonly TimeSpan MinRunGap     = TimeSpan.FromHours(20);
    private const           string   LastRunFile   = "abuseipdb_last_run.txt";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<AbuseIpDbWorker> _logger;

    public AbuseIpDbWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<AbuseIpDbWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AbuseIpDbWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AbuseIpDbWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        // Skip if a successful run already happened within the last 20 hours
        if (File.Exists(LastRunFile) &&
            DateTime.TryParse(await File.ReadAllTextAsync(LastRunFile, ct), out var lastRun) &&
            DateTime.UtcNow - lastRun < MinRunGap)
        {
            _logger.LogInformation("AbuseIpDbWorker: skipping — last run was {Ago:0.1f}h ago.",
                (DateTime.UtcNow - lastRun).TotalHours);
            return;
        }

        var abuseKey = _config["ExternalApis:AbuseIpDbApiKey"];
        var apiBase = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var apiKey = _config["ApiKey"];

        var abuseClient = _httpClientFactory.CreateClient("AbuseIPDB");
        abuseClient.DefaultRequestHeaders.TryAddWithoutValidation("Key", abuseKey);
        abuseClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json");

        var response = await abuseClient.GetAsync(
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("AbuseIPDB API returned {StatusCode}", response.StatusCode);
            return;
        }

        var root = await response.Content.ReadFromJsonAsync<AbuseBlacklistResponse>(cancellationToken: ct);
        if (root?.Data is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", apiKey);

        int sent = 0;
        foreach (var entry in root.Data)
        {
            var severity = entry.AbuseConfidenceScore >= 95 ? "Critical" : "High";

            var dto = new ExternalIncidentDto(
                SourceIp: entry.IpAddress,
                AttackType: "Threat Intelligence - Blacklisted IP",
                Severity: severity,
                DataSource: "AbuseIPDB",
                SourceCountry: entry.CountryCode,
                DestinationPort: null,
                Protocol: null,
                Description: $"AbuseIPDB blacklisted IP. Confidence: {entry.AbuseConfidenceScore}%. Last reported: {entry.LastReportedAt}"
            );

            var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/incidents/external", dto, ct);
            if (postResp.IsSuccessStatusCode)
                sent++;
            else
                _logger.LogWarning("Failed to POST AbuseIPDB entry {Ip}: {Status}", entry.IpAddress, postResp.StatusCode);
        }

        _logger.LogInformation("AbuseIpDbWorker: sent {Count} entries.", sent);

        // Persist last-run timestamp so restarts don't burn an extra request
        await File.WriteAllTextAsync(LastRunFile, DateTime.UtcNow.ToString("O"), ct);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class AbuseBlacklistResponse
    {
        [JsonPropertyName("data")]
        public List<AbuseEntry>? Data { get; set; }
    }

    private sealed class AbuseEntry
    {
        [JsonPropertyName("ipAddress")]
        public string IpAddress { get; set; } = string.Empty;

        [JsonPropertyName("abuseConfidenceScore")]
        public int AbuseConfidenceScore { get; set; }

        [JsonPropertyName("countryCode")]
        public string? CountryCode { get; set; }

        [JsonPropertyName("lastReportedAt")]
        public string? LastReportedAt { get; set; }
    }
}
