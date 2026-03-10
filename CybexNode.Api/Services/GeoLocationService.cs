using MaxMind.GeoIP2;

namespace CybexNode.Api.Services;

public class GeoLocationService : IDisposable
{
    private readonly DatabaseReader _reader;

    public GeoLocationService(IWebHostEnvironment env, IConfiguration config)
    {
        var dbPath = config["ExternalApis:MaxMindDbPath"] ?? "GeoLite2-City.mmdb";
        var fullPath = Path.IsPathRooted(dbPath) ? dbPath : Path.Combine(env.ContentRootPath, dbPath);
        _reader = new DatabaseReader(fullPath);
    }

    public (double? Lat, double? Lng, string? Country, string? City) Lookup(string ip)
    {
        try
        {
            var response = _reader.City(ip);
            return (response.Location.Latitude, response.Location.Longitude,
                    response.Country.IsoCode, response.City.Name);
        }
        catch
        {
            return (null, null, null, null);
        }
    }

    public void Dispose() => _reader.Dispose();
}
