using CybexNode.Api.Authentication;
using CybexNode.Api.Data;
using CybexNode.Api.Dtos;
using CybexNode.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CybexNode.Api.Controllers;

[ApiController]
[Route("api/cve")]
public class CveController : ControllerBase
{
    private readonly CybexDbContext _db;
    private readonly ILogger<CveController> _logger;

    public CveController(CybexDbContext db, ILogger<CveController> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Receives a CVE from CISA KEV and persists it in the CveEntries table.
    /// </summary>
    [HttpPost]
    [Authorize(AuthenticationSchemes = ApiKeyAuthHandler.SchemeName)]
    [ProducesResponseType(typeof(CveResponseDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Create([FromBody] CreateCveDto dto)
    {
        var exists = await _db.CveEntries.AnyAsync(c => c.CveId == dto.CveId);
        if (exists)
            return Conflict(new { error = $"{dto.CveId} already exists." });

        var entry = new CveEntry
        {
            Id = Guid.NewGuid(),
            CveId = dto.CveId,
            VendorProject = dto.VendorProject,
            Product = dto.Product,
            VulnerabilityName = dto.VulnerabilityName,
            Description = dto.Description,
            Severity = dto.Severity,
            RequiredAction = dto.RequiredAction,
            DueDate = dto.DueDate,
        };

        _db.CveEntries.Add(entry);
        await _db.SaveChangesAsync();

        _logger.LogInformation("CVE {CveId} saved (Id={Id}).", entry.CveId, entry.Id);

        return CreatedAtAction(nameof(GetByCveId), new { cveId = entry.CveId }, ToDto(entry));
    }

    /// <summary>
    /// Lists CVEs with optional severity filter and pagination.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public async Task<IActionResult> List(
        [FromQuery] string? severity = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        pageSize = Math.Clamp(pageSize, 1, 100);
        page     = Math.Max(page, 1);

        var query = _db.CveEntries.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(severity))
            query = query.Where(c => c.Severity == severity);

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescending(c => c.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(c => ToDto(c))
            .ToListAsync();

        return Ok(new { total, page, pageSize, items });
    }

    /// <summary>
    /// Returns a single CVE by its CVE ID (e.g. CVE-2024-1234).
    /// </summary>
    [HttpGet("{cveId}")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(CveResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetByCveId(string cveId)
    {
        var entry = await _db.CveEntries
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CveId == cveId);

        if (entry is null)
            return NotFound(new { error = $"{cveId} not found." });

        return Ok(ToDto(entry));
    }

    private static CveResponseDto ToDto(CveEntry c) => new(
        c.Id, c.CveId, c.VendorProject, c.Product,
        c.VulnerabilityName, c.Description, c.Severity,
        c.RequiredAction, c.DueDate, c.CreatedAt
    );
}
