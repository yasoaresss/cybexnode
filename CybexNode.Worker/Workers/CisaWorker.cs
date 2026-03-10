using System.Net.Http.Json;
using System.Text.Json.Serialization;
using CybexNode.Worker.Dtos;

namespace CybexNode.Worker.Workers;

public class CisaWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<CisaWorker> _logger;

    // In-memory dedup across cycles (DB unique index is the final guard)
    private readonly HashSet<string> _sentCves = new(StringComparer.OrdinalIgnoreCase);

    public CisaWorker(IHttpClientFactory httpClientFactory, IConfiguration config, ILogger<CisaWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CisaWorker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FetchAndPostAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CisaWorker error during fetch cycle.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task FetchAndPostAsync(CancellationToken ct)
    {
        var apiBase = _config["ApiBaseUrl"] ?? "http://localhost:5277";
        var apiKey  = _config["ApiKey"];

        var cisaClient = _httpClientFactory.CreateClient("CISA");
        var response = await cisaClient.GetAsync(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("CISA API returned {StatusCode}", response.StatusCode);
            return;
        }

        var root = await response.Content.ReadFromJsonAsync<CisaKevResponse>(cancellationToken: ct);
        if (root?.Vulnerabilities is null) return;

        var apiClient = _httpClientFactory.CreateClient("API");
        apiClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Api-Key", apiKey);

        int sent = 0;
        foreach (var vuln in root.Vulnerabilities)
        {
            if (!_sentCves.Add(vuln.CveId))
                continue;

            var severity = vuln.KnownRansomwareCampaignUse == "Known" ? "Critical" : "High";

            DateTime? dueDate = null;
            if (DateTime.TryParse(vuln.DueDate, out var parsed))
                dueDate = parsed;

            var dto = new CreateCveDto(
                CveId:             vuln.CveId,
                VendorProject:     vuln.VendorProject,
                Product:           vuln.Product,
                VulnerabilityName: vuln.VulnerabilityName,
                Description:       vuln.ShortDescription,
                Severity:          severity,
                RequiredAction:    vuln.RequiredAction,
                DueDate:           dueDate
            );

            var postResp = await apiClient.PostAsJsonAsync($"{apiBase}/api/cve", dto, ct);

            // 201 = created, 409 = already exists (unique constraint) — both are fine
            if (postResp.IsSuccessStatusCode || (int)postResp.StatusCode == 409)
                sent++;
            else
                _logger.LogWarning("Failed to POST CISA CVE {CveId}: {Status}", vuln.CveId, postResp.StatusCode);
        }

        _logger.LogInformation("CisaWorker: processed {Count} CVEs.", sent);
    }

    // ── Response models ────────────────────────────────────────────────────────

    private sealed class CisaKevResponse
    {
        [JsonPropertyName("vulnerabilities")]
        public List<CisaVulnerability>? Vulnerabilities { get; set; }
    }

    private sealed class CisaVulnerability
    {
        [JsonPropertyName("cveID")]
        public string CveId { get; set; } = string.Empty;

        [JsonPropertyName("vendorProject")]
        public string VendorProject { get; set; } = string.Empty;

        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("vulnerabilityName")]
        public string VulnerabilityName { get; set; } = string.Empty;

        [JsonPropertyName("dateAdded")]
        public string DateAdded { get; set; } = string.Empty;

        [JsonPropertyName("dueDate")]
        public string? DueDate { get; set; }

        [JsonPropertyName("shortDescription")]
        public string ShortDescription { get; set; } = string.Empty;

        [JsonPropertyName("requiredAction")]
        public string RequiredAction { get; set; } = string.Empty;

        [JsonPropertyName("knownRansomwareCampaignUse")]
        public string? KnownRansomwareCampaignUse { get; set; }
    }
}
