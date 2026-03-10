using System.Net.Http.Json;
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
            response.EnsureSuccessStatusCode();
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
