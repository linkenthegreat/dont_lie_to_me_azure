using System.Net.Http.Json;
using System.Text.Json;
using DontLieToMe.Web.Models;

namespace DontLieToMe.Web.Services;

public class ApiClient : IApiClient
{
    private readonly HttpClient _http;

    public ApiClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<ChatResponse> SendChatMessageAsync(ChatRequest request)
    {
        try
        {
            var response = await _http.PostAsJsonAsync("chat", request);
            if (!response.IsSuccessStatusCode)
            {
                var status = (int)response.StatusCode;
                var reason = response.ReasonPhrase ?? "HTTP error";
                var body = await response.Content.ReadAsStringAsync();

                // Backend returns a JSON payload with `error` and `error_type` on failure.
                // Surface that detail so production issues can be diagnosed from the UI.
                if (!string.IsNullOrWhiteSpace(body))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(body);
                        if (doc.RootElement.TryGetProperty("error", out var errProp))
                        {
                            return new ChatResponse { Error = $"{status} {reason}: {errProp.GetString()}" };
                        }
                    }
                    catch (JsonException)
                    {
                        // Ignore parse errors and fall back to raw body text.
                    }

                    return new ChatResponse { Error = $"{status} {reason}: {body}" };
                }

                return new ChatResponse { Error = $"{status} {reason}" };
            }

            return await response.Content.ReadFromJsonAsync<ChatResponse>()
                   ?? new ChatResponse { Error = "Empty response" };
        }
        catch (Exception ex)
        {
            return new ChatResponse { Error = ex.Message };
        }
    }

    public async Task SubmitFeedbackAsync(FeedbackRequest request)
    {
        await _http.PostAsJsonAsync("feedback", request);
    }

    public async Task<List<HistoryEntry>> GetHistoryAsync(string sessionId, int limit = 10)
    {
        try
        {
            var result = await _http.GetFromJsonAsync<List<HistoryEntry>>($"history?session_id={sessionId}&limit={limit}");
            return result ?? new();
        }
        catch
        {
            return new();
        }
    }

    public string GetExportUrl(string sessionId, string format)
    {
        return $"{_http.BaseAddress}export?session_id={sessionId}&format={format}";
    }
}
