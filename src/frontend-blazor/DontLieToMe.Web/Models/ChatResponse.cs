using System.Text.Json;
using System.Text.Json.Serialization;

namespace DontLieToMe.Web.Models;

public class ChatResponse
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("data")]
    public Dictionary<string, JsonElement>? Data { get; set; }

    [JsonPropertyName("agent_used")]
    public string? AgentUsed { get; set; }

    [JsonPropertyName("trace")]
    public OrchestrationTrace? Trace { get; set; }

    [JsonPropertyName("session_id")]
    public string? SessionId { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}
