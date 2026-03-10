namespace CybexNode.Api.Dtos;

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
