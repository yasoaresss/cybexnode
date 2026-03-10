namespace CybexNode.Worker.Dtos;

public record ExternalIncidentDto(
    string SourceIp,
    string AttackType,
    string Severity,
    string DataSource,
    string? SourceCountry,
    int? DestinationPort,
    string? Protocol,
    string? Description
);

public record CreateCveDto(
    string CveId,
    string VendorProject,
    string Product,
    string VulnerabilityName,
    string Description,
    string Severity,
    string RequiredAction,
    DateTime? DueDate
);
