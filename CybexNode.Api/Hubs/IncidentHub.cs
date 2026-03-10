using Microsoft.AspNetCore.SignalR;

namespace CybexNode.Api.Hubs;

public class IncidentHub : Hub
{
    public async Task JoinSensorGroup(string sensorId)
        => await Groups.AddToGroupAsync(Context.ConnectionId, $"sensor:{sensorId}");

    public async Task LeaveSensorGroup(string sensorId)
        => await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"sensor:{sensorId}");
}
