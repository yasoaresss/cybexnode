namespace CybexNode.Api.Models;

public class CveEntry
{
    public Guid Id { get; set; }
    public string CveId { get; set; } = string.Empty;
    public string VendorProject { get; set; } = string.Empty;
    public string Product { get; set; } = string.Empty;
    public string VulnerabilityName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string RequiredAction { get; set; } = string.Empty;
    public DateTime? DueDate { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
