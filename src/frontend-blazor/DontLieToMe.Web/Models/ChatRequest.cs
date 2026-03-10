using System.Text.Json.Serialization;

namespace DontLieToMe.Web.Models;

public class ChatRequest
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("images")]
    public List<string>? Images { get; set; }

    [JsonPropertyName("session_id")]
    public string? SessionId { get; set; }

    [JsonPropertyName("context")]
    public ChatContext? Context { get; set; }
}
