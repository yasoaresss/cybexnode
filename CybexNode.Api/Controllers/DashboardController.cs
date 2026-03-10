using CybexNode.Api.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CybexNode.Api.Controllers;

[ApiController]
[Route("api/dashboard")]
[AllowAnonymous]
public class DashboardController : ControllerBase
{
    private readonly CybexDbContext _db;
    private readonly ILogger<DashboardController> _log;

    public DashboardController(CybexDbContext db, ILogger<DashboardController> log)
    {
        _db  = db;
        _log = log;
    }

    /// <summary>
    /// Returns aggregate dashboard statistics filtered to honeypot sources only.
    /// Query params: state (ignored for now), hours (default 12).
    /// </summary>
    [HttpGet("stats")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Stats([FromQuery] string? state = null, [FromQuery] int hours = 12)
    {
        hours = Math.Clamp(hours, 1, 168);
        var since = DateTime.UtcNow.AddHours(-hours);

        // ── Diagnostic: count ALL incidents in window, then by DataSource ────────
        var countAll = await _db.Incidents.CountAsync(i => i.CreatedAt >= since);
        var countFiltered = await _db.Incidents.CountAsync(i =>
            i.CreatedAt >= since &&
            (i.DataSource == "HoneypotSP" || i.DataSource == "Cowrie"));
        var distinctSources = await _db.Incidents
            .Where(i => i.CreatedAt >= since)
            .GroupBy(i => i.DataSource ?? "null")
            .Select(g => new { Source = g.Key, Count = g.Count() })
            .ToListAsync();

        Console.WriteLine($"[Stats] cutoff={since:u} countAll={countAll} countFiltered={countFiltered}");
        Console.WriteLine($"[Stats] DataSources na janela: {string.Join(", ", distinctSources.Select(s => $"{s.Source}={s.Count}"))}");
        // ─────────────────────────────────────────────────────────────────────────

        // HoneypotSP / Cowrie incidents all originate from the São Paulo sensor.
        // If a specific state is requested and it isn't SP, return zeros.
        var stateFilter = state?.ToUpperInvariant();
        if (stateFilter != null && stateFilter != "SP")
        {
            return Ok(new
            {
                total = 0,
                bySeverity = new { critical = 0, high = 0, medium = 0, low = 0 },
                top3AttackTypes = new List<string>(),
                top3SourceIps   = new List<string>(),
                volumeByHour    = Enumerable.Range(0, hours).Select(h => new { hour = since.AddHours(h).ToString("HH") + "h", count = 0 }).ToList(),
            });
        }

        var incidents = await _db.Incidents
            .AsNoTracking()
            .Where(i => i.CreatedAt >= since
                     && (i.DataSource == "HoneypotSP" || i.DataSource == "Cowrie"))
            .Select(i => new
            {
                i.Severity,
                i.AttackType,
                i.SourceIp,
                i.CreatedAt,
                i.DataSource,
            })
            .ToListAsync();

        var total = incidents.Count;

        // Total desde meia-noite de Brasília (UTC-3)
        var nowUtc              = DateTime.UtcNow;
        var todayBrtMidnightUtc = nowUtc.Date.AddHours(3); // 00:00 BRT = 03:00 UTC
        if (todayBrtMidnightUtc > nowUtc)
            todayBrtMidnightUtc = todayBrtMidnightUtc.AddDays(-1);
        var totalHoje = incidents.Count(i => i.CreatedAt >= todayBrtMidnightUtc);

        var cntCrit   = incidents.Count(i => i.Severity == "Critical");
        var cntHigh   = incidents.Count(i => i.Severity == "High");
        var cntMedium = incidents.Count(i => i.Severity == "Medium");
        var cntLow    = incidents.Count(i => i.Severity == "Low");

        Console.WriteLine($"[Stats] total={total} crit={cntCrit} high={cntHigh} med={cntMedium} low={cntLow}");
        Console.WriteLine($"[Stats] Severities distintas: {string.Join(", ", incidents.Select(i => i.Severity ?? "null").Distinct())}");

        var bySeverity = new
        {
            Critical = cntCrit,
            High     = cntHigh,
            Medium   = cntMedium,
            Low      = cntLow,
        };

        var top3AttackTypes = incidents
            .Where(i => !string.IsNullOrEmpty(i.AttackType))
            .GroupBy(i => i.AttackType!)
            .OrderByDescending(g => g.Count())
            .Take(3)
            .Select(g => new { type = g.Key, count = g.Count() })
            .ToList();

        var top3SourceIps = incidents
            .GroupBy(i => i.SourceIp)
            .OrderByDescending(g => g.Count())
            .Take(3)
            .Select(g => new { ip = g.Key, count = g.Count() })
            .ToList();

        var volumeByHour = Enumerable.Range(0, hours)
            .Select(h =>
            {
                var slotStart = since.AddHours(h);
                var slotEnd   = slotStart.AddHours(1);
                return new
                {
                    hour  = slotStart.ToString("HH") + "h",
                    count = incidents.Count(i => i.CreatedAt >= slotStart && i.CreatedAt < slotEnd),
                };
            })
            .ToList();

        return Ok(new
        {
            total,
            totalHoje,
            bySeverity,
            top3AttackTypes,
            top3SourceIps,
            volumeByHour,
        });
    }
}
