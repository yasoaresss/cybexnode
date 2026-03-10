namespace CybexNode.Api.Dtos;

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

public record CveResponseDto(
    Guid Id,
    string CveId,
    string VendorProject,
    string Product,
    string VulnerabilityName,
    string Description,
    string Severity,
    string RequiredAction,
    DateTime? DueDate,
    DateTime CreatedAt
);
