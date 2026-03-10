using System.Text.Json;
using System.Text.Json.Serialization;
namespace DontLieToMe.Web.Models;

public class HistoryEntry
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    [JsonPropertyName("sessionId")]
    public string? SessionId { get; set; }
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "";
    [JsonPropertyName("inputText")]
    public string InputText { get; set; } = "";
    [JsonPropertyName("result")]
    public JsonElement? Result { get; set; }
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";
}
