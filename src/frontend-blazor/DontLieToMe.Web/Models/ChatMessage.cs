namespace DontLieToMe.Web.Models;

public class ChatMessage
{
    public string Role { get; set; } = "user"; // "user" or "assistant"
    public string Content { get; set; } = "";
    public List<string>? Images { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public ChatResponse? Response { get; set; } // Only for assistant messages
}
