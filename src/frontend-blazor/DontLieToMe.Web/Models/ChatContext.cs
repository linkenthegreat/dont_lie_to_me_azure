using System.Text.Json.Serialization;

namespace DontLieToMe.Web.Models;

public class ChatContext
{
    [JsonPropertyName("location")]
    public string? Location { get; set; }

    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("conversation_history")]
    public List<ConversationMessage>? ConversationHistory { get; set; }
}

public class ConversationMessage
{
    [JsonPropertyName("role")]
    public string Role { get; set; } = "";

    [JsonPropertyName("content")]
    public string Content { get; set; } = "";
}
