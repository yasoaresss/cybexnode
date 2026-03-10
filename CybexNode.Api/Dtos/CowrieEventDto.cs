using System.Text.Json.Serialization;

namespace CybexNode.Api.Dtos;

/// <summary>
/// Maps the JSON log format emitted by the Cowrie SSH/Telnet honeypot.
/// See: https://cowrie.readthedocs.io/en/latest/
/// </summary>
public class CowrieEventDto
{
    [JsonPropertyName("eventid")]
    public string EventId { get; set; } = string.Empty;

    [JsonPropertyName("src_ip")]
    public string SrcIp { get; set; } = string.Empty;

    [JsonPropertyName("src_port")]
    public int? SrcPort { get; set; }

    [JsonPropertyName("dst_ip")]
    public string? DstIp { get; set; }

    [JsonPropertyName("dst_port")]
    public int? DstPort { get; set; }

    [JsonPropertyName("session")]
    public string? Session { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("sensor")]
    public string? Sensor { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    // Login attempt fields
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    // Command execution fields
    [JsonPropertyName("input")]
    public string? Input { get; set; }

    // File download fields
    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("outfile")]
    public string? OutFile { get; set; }
}
