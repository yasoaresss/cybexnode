using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class OtxWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<OtxWorker> _logger;

    public OtxWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<OtxWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("OtxWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OtxWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        var otxKey = _config["ExternalApis:OtxApiKey"];
        var apiBase = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var apiKey = _config["ApiKey"];

        var otxClient = _httpClientFactory.CreateClient("OTX");
        otxClient.DefaultRequestHeaders.TryAddWithoutValidation("X-OTX-API-KEY", otxKey);

        var response = await otxClient.GetAsync(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OTX API returned {StatusCode}", response.StatusCode);
            return;
        }

        var root = await response.Content.ReadFromJsonAsync<OtxPulsesResponse>(cancellationToken: ct);
        if (root?.Results is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", apiKey);

        int sent = 0;
        foreach (var pulse in root.Results)
        {
            var ipv4Indicators = pulse.Indicators?
                .Where(i => i.Type == "IPv4")
                .ToList() ?? [];

            foreach (var indicator in ipv4Indicators)
            {
                var indicatorDetail = indicator.Description ?? indicator.Title ?? string.Empty;
                var description = !string.IsNullOrWhiteSpace(pulse.Description)
                    ? pulse.Description
                    : (!string.IsNullOrWhiteSpace(indicatorDetail) ? indicatorDetail : $"OTX pulse: {pulse.Name}");

                var dto = new ExternalIncidentDto(
                    SourceIp: indicator.Indicator,
                    AttackType: pulse.Name,
                    Severity: "High",
                    DataSource: "OTX",
                    SourceCountry: indicator.CountryCode,
                    DestinationPort: null,
                    Protocol: null,
                    Description: description
                );

                var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/incidents/external", dto, ct);
                if (postResp.IsSuccessStatusCode)
                    sent++;
                else
                    _logger.LogWarning("Failed to POST OTX indicator {Ip}: {Status}", indicator.Indicator, postResp.StatusCode);
            }
        }

        _logger.LogInformation("OtxWorker: sent {Count} indicators.", sent);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class OtxPulsesResponse
    {
        [JsonPropertyName("results")]
        public List<OtxPulse>? Results { get; set; }
    }

    private sealed class OtxPulse
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("indicators")]
        public List<OtxIndicator>? Indicators { get; set; }
    }

    private sealed class OtxIndicator
    {
        [JsonPropertyName("indicator")]
        public string Indicator { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("country_code")]
        public string? CountryCode { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }
    }
}
