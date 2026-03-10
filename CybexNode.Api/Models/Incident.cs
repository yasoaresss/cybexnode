namespace CybexNode.Api.Models;

public class Incident
{
    public int Id { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public int? SourcePort { get; set; }
    public int? DestinationPort { get; set; }
    public string? Protocol { get; set; }
    public string? AttackType { get; set; }
    public string? Payload { get; set; }
    public string RawLog { get; set; } = string.Empty;
    public string? SensorId { get; set; }
    public string? SessionId { get; set; }
    public string? EventId { get; set; }
    public string? Severity { get; set; }
    public string? DataSource { get; set; }
    public string? SourceCountry { get; set; }
    public string? SourceCity { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}
