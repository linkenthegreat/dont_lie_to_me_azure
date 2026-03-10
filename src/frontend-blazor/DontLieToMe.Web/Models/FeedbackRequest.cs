using System.Text.Json.Serialization;
namespace DontLieToMe.Web.Models;

public class FeedbackRequest
{
    [JsonPropertyName("rating")]
    public int Rating { get; set; }
    [JsonPropertyName("session_id")]
    public string? SessionId { get; set; }
}
