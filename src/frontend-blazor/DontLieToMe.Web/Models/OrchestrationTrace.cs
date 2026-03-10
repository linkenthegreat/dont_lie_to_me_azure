using System.Text.Json.Serialization;

namespace DontLieToMe.Web.Models;

public class OrchestrationTrace
{
    [JsonPropertyName("route_path")]
    public List<string>? RoutePath { get; set; }

    [JsonPropertyName("routing_decision")]
    public string? RoutingDecision { get; set; }

    [JsonPropertyName("duration_ms")]
    public double? DurationMs { get; set; }

    [JsonPropertyName("model_used")]
    public string? ModelUsed { get; set; }

    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; set; }

    [JsonPropertyName("fallback_triggered")]
    public bool FallbackTriggered { get; set; }
}
