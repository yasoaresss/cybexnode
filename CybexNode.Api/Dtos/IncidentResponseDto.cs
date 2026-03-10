namespace CybexNode.Api.Dtos;

public record IncidentResponseDto(
    int    Id,
    string SourceIp,
    string DestinationIp,
    int?   SourcePort,
    int?   DestinationPort,
    string Protocol,
    string AttackType,
    string Severity,
    string SourceCountry,
    string SourceCity,
    double Latitude,
    double Longitude,
    string DataSource,
    string Status,
    string CreatedAt
);
