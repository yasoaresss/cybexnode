using System.Text.Json;
using CybexNode.Api.Authentication;
using CybexNode.Api.Data;
using CybexNode.Api.Dtos;
using CybexNode.Api.Hubs;
using CybexNode.Api.Models;
using CybexNode.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

namespace CybexNode.Api.Controllers;

[ApiController]
[Route("api/incidents")]
[Authorize(AuthenticationSchemes = ApiKeyAuthHandler.SchemeName)]
public class IncidentsController : ControllerBase
{
    private readonly CybexDbContext _db;
    private readonly IHubContext<IncidentHub> _hub;
    private readonly ILogger<IncidentsController> _logger;
    private readonly GeoLocationService _geo;

    public IncidentsController(
        CybexDbContext db,
        IHubContext<IncidentHub> hub,
        ILogger<IncidentsController> logger,
        GeoLocationService geo)
    {
        _db = db;
        _hub = hub;
        _logger = logger;
        _geo = geo;
    }

    /// <summary>
    /// Returns the most recent incidents (newest first).
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    [ProducesResponseType(typeof(IncidentResponseDto[]), StatusCodes.Status200OK)]
    public async Task<IActionResult> List([FromQuery] int limit = 50)
    {
        limit = Math.Clamp(limit, 1, 200);

        var rows = await _db.Incidents
            .AsNoTracking()
            .OrderByDescending(i => i.CreatedAt)
            .Take(limit)
            .ToListAsync();

        return Ok(rows.Select(ToDto));
    }

    /// <summary>
    /// Receives a Cowrie honeypot event, persists it as an Incident + Alert
    /// and broadcasts the new incident via SignalR.
    /// </summary>
    [HttpPost("cowrie")]
    [ProducesResponseType(typeof(IncidentCreatedDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> PostCowrie([FromBody] CowrieEventDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.SrcIp))
            return BadRequest(new { error = "src_ip is required." });

        if (IsPrivateIp(dto.SrcIp))
        {
            _logger.LogDebug("Cowrie: discarding private-IP event from {SrcIp}", dto.SrcIp);
            return Ok(new { skipped = true, reason = "private IP" });
        }

        var severity = ResolveSeverity(dto.EventId);

        var (lat, lng, geoCountry, geoCity) = _geo.Lookup(dto.SrcIp);

        var incident = new Incident
        {
            SourceIp = dto.SrcIp,
            SourcePort = dto.SrcPort,
            DestinationPort = dto.DstPort,
            Protocol = "SSH",
            AttackType = ResolveAttackType(dto.EventId),
            Severity = severity,
            DataSource = "HoneypotSP",
            SourceCountry = geoCountry,
            SourceCity = geoCity,
            Latitude = lat,
            Longitude = lng,
            Payload = ResolvePayload(dto),
            RawLog = JsonSerializer.Serialize(dto),
            SensorId = dto.Sensor,
            SessionId = dto.Session,
            EventId = dto.EventId,
            Timestamp = dto.Timestamp == default ? DateTime.UtcNow : dto.Timestamp,
        };

        var alert = new Alert
        {
            Severity = severity,
            Message = dto.Message ?? $"Cowrie event {dto.EventId} from {dto.SrcIp}",
        };

        incident.Alerts.Add(alert);

        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _logger.LogInformation(
            "Cowrie incident #{Id} saved. EventId={EventId}, SrcIp={SrcIp}",
            incident.Id, incident.EventId, incident.SourceIp);

        // Broadcast to all SignalR clients and to the sensor group
        var broadcastPayload = ToDto(incident);

        await _hub.Clients.All.SendAsync("IncidentCreated", broadcastPayload);

        if (!string.IsNullOrWhiteSpace(incident.SensorId))
            await _hub.Clients.Group($"sensor:{incident.SensorId}")
                .SendAsync("IncidentCreated", broadcastPayload);

        var response = new IncidentCreatedDto(incident.Id, $"Incident #{incident.Id} recorded successfully.");
        return CreatedAtAction(null, new { id = incident.Id }, response);
    }

    /// <summary>
    /// One-time migration: renames DataSource 'Cowrie' → 'HoneypotSP' and normalises
    /// legacy AttackType values for existing honeypot rows.
    /// </summary>
    [HttpPost("migrate-datasource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> MigrateDataSource()
    {
        var renamedDs = await _db.Database.ExecuteSqlRawAsync(
            "UPDATE Incidents SET DataSource = 'HoneypotSP' WHERE DataSource = 'Cowrie'");

        var normalised = await _db.Database.ExecuteSqlRawAsync(@"
            UPDATE Incidents
            SET AttackType = 'Reconnaissance — Port Scan'
            WHERE DataSource IN ('Cowrie', 'HoneypotSP')
              AND AttackType IN (
                'Unknown',
                'cowrie.session.connect',
                'cowrie.session.closed',
                'cowrie.client.version',
                'cowrie.client.kex',
                'cowrie.client.size',
                'cowrie.client.var',
                'cowrie.session.params',
                'Reconnaissance'
              )");

        _logger.LogInformation(
            "MigrateDataSource: renamed {Ds} DataSource rows, normalised {At} AttackType rows.",
            renamedDs, normalised);

        return Ok(new { renamedDataSource = renamedDs, normalisedAttackType = normalised });
    }

    /// <summary>
    /// Receives an external threat intelligence event (OTX, AbuseIPDB, FeodoTracker, CISA),
    /// geolocates the source IP, persists it as an Incident and broadcasts via SignalR.
    /// </summary>
    [HttpPost("external")]
    [ProducesResponseType(typeof(IncidentCreatedDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> PostExternal([FromBody] ExternalIncidentDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.SourceIp))
            return BadRequest(new { error = "SourceIp is required." });

        _logger.LogDebug("PostExternal received — DataSource={DataSource}, AttackType={AttackType}, SourceIp={SourceIp}",
            dto.DataSource, dto.AttackType, dto.SourceIp);

        if (string.IsNullOrWhiteSpace(dto.DataSource))
            _logger.LogWarning("PostExternal: DataSource arrived NULL or empty for SourceIp={SourceIp}. Full dto: {@Dto}", dto.SourceIp, dto);

        var (lat, lng, geoCountry, _) = _geo.Lookup(dto.SourceIp);

        var incident = new Incident
        {
            SourceIp = dto.SourceIp,
            DestinationPort = dto.DestinationPort,
            Protocol = dto.Protocol,
            AttackType = dto.AttackType,
            Severity = dto.Severity,
            DataSource = dto.DataSource,
            SourceCountry = dto.SourceCountry ?? geoCountry,
            Latitude = lat,
            Longitude = lng,
            Payload = dto.Description,
            RawLog = JsonSerializer.Serialize(dto),
            Timestamp = DateTime.UtcNow,
        };

        var alert = new Alert
        {
            Severity = dto.Severity,
            Message = dto.Description ?? $"[{dto.DataSource}] {dto.AttackType} from {dto.SourceIp}",
        };

        incident.Alerts.Add(alert);

        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _logger.LogInformation(
            "External incident #{Id} saved. Source={DataSource}, AttackType={AttackType}, SrcIp={SrcIp}",
            incident.Id, incident.DataSource, incident.AttackType, incident.SourceIp);

        var broadcastPayload = ToDto(incident);

        await _hub.Clients.All.SendAsync("IncidentCreated", broadcastPayload);

        var response = new IncidentCreatedDto(incident.Id, $"External incident #{incident.Id} recorded successfully.");
        return CreatedAtAction(null, new { id = incident.Id }, response);
    }

    // --------------- helpers ---------------

    private static string ResolveAttackType(string eventId) => eventId switch
    {
        "cowrie.login.failed"         => "Brute Force — Login Failed",
        "cowrie.login.success"        => "Brute Force — Login Success",
        "cowrie.command.input"        => "Command Execution",
        "cowrie.command.failed"       => "Command Execution",
        "cowrie.direct-tcpip.data"    => "Port Forwarding",
        "cowrie.direct-tcpip"         => "Port Forwarding",
        "cowrie.session.file_download"=> "Malware Download",
        "cowrie.session.file_upload"  => "File Upload",
        "cowrie.session.connect"      => "Reconnaissance — Port Scan",
        "cowrie.session.closed"       => "Reconnaissance — Port Scan",
        "cowrie.client.version"       => "Reconnaissance — Port Scan",
        "cowrie.client.kex"           => "Reconnaissance — Port Scan",
        "cowrie.client.size"          => "Reconnaissance — Port Scan",
        "cowrie.client.var"           => "Reconnaissance — Port Scan",
        "cowrie.session.params"       => "Reconnaissance — Port Scan",
        _                             => "Reconnaissance — Port Scan",
    };

    private static string ResolveSeverity(string eventId) => eventId switch
    {
        "cowrie.session.connect" => "Low",
        "cowrie.login.failed" => "Medium",
        "cowrie.login.success" => "High",
        "cowrie.command.input" => "High",
        "cowrie.direct-tcpip.data" => "Critical",
        "cowrie.session.file_download" => "Critical",
        "cowrie.session.file_upload" => "Critical",
        _ => "Medium",
    };

    private static string? ResolvePayload(CowrieEventDto dto)
    {
        if (!string.IsNullOrWhiteSpace(dto.Input))
            return $"Command: {dto.Input}";
        if (!string.IsNullOrWhiteSpace(dto.Username))
            return $"Login attempt — user: {dto.Username}";
        if (!string.IsNullOrWhiteSpace(dto.Url))
            return $"Download URL: {dto.Url}";
        return null;
    }

    private static bool IsPrivateIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) return true;
        var b = addr.GetAddressBytes();
        return b[0] == 10
            || b[0] == 127
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168);
    }

    private static IncidentResponseDto ToDto(Incident i) => new(
        Id:             i.Id,
        SourceIp:       i.SourceIp,
        DestinationIp:  string.Empty,
        SourcePort:     i.SourcePort,
        DestinationPort:i.DestinationPort,
        Protocol:       i.Protocol       ?? string.Empty,
        AttackType:     i.AttackType     ?? string.Empty,
        Severity:       i.Severity       ?? string.Empty,
        SourceCountry:  i.SourceCountry  ?? string.Empty,
        SourceCity:     i.SourceCity     ?? string.Empty,
        Latitude:       i.Latitude       ?? 0,
        Longitude:      i.Longitude      ?? 0,
        DataSource:     i.DataSource     ?? string.Empty,
        Status:         "active",
        CreatedAt:      i.CreatedAt.ToString("o")
    );
}
