using DontLieToMe.Web.Models;

namespace DontLieToMe.Web.Services;

public interface IApiClient
{
    Task<ChatResponse> SendChatMessageAsync(ChatRequest request);
    Task SubmitFeedbackAsync(FeedbackRequest request);
    Task<List<HistoryEntry>> GetHistoryAsync(string sessionId, int limit = 10);
    string GetExportUrl(string sessionId, string format);
}
