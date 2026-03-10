using DontLieToMe.Web.Models;

namespace DontLieToMe.Web.Services;

public class MockApiClient : IApiClient
{
    private static readonly string[] MockResponses =
    [
        "This message contains several red flags commonly associated with scam communications. The urgency language and request for personal information are classic social engineering tactics.",
        "Based on my analysis, this appears to be a phishing attempt. The sender is impersonating a legitimate organization to trick you into revealing sensitive information.",
        "This looks safe to me. The message doesn't contain any suspicious patterns or known scam indicators.",
        "I've detected some suspicious elements in this message. While it may not be a confirmed scam, I'd recommend proceeding with caution and verifying the sender's identity.",
        "This is a common type of advance-fee scam. The promise of a large reward in exchange for a small upfront payment is a well-known fraud technique."
    ];

    private static readonly string[] MockClassifications =
    [
        "SCAM", "LIKELY_SCAM", "SUSPICIOUS", "SAFE"
    ];

    public async Task<ChatResponse> SendChatMessageAsync(ChatRequest request)
    {
        // Simulate network delay
        await Task.Delay(Random.Shared.Next(500, 1500));

        var isUrl = request.Message.Contains("http://") || request.Message.Contains("https://");
        var classification = MockClassifications[Random.Shared.Next(MockClassifications.Length)];
        var confidence = classification switch
        {
            "SCAM" => 0.92,
            "LIKELY_SCAM" => 0.78,
            "SUSPICIOUS" => 0.55,
            _ => 0.15
        };

        var message = MockResponses[Random.Shared.Next(MockResponses.Length)];

        return new ChatResponse
        {
            Message = message,
            AgentUsed = isUrl ? "url_analyzer" : "classifier_chain",
            SessionId = request.SessionId,
            Trace = new OrchestrationTrace
            {
                RoutePath = isUrl
                    ? new List<string> { "receptionist", "url_analyzer" }
                    : new List<string> { "receptionist", "classifier", "analyzer", "guide" },
                RoutingDecision = isUrl ? "URL detected in input" : "Text analysis requested",
                DurationMs = Random.Shared.Next(200, 800),
                ModelUsed = "mock-gpt-4o",
                Timestamp = DateTime.UtcNow.ToString("o"),
                FallbackTriggered = false
            }
        };
    }

    public Task SubmitFeedbackAsync(FeedbackRequest request)
    {
        return Task.CompletedTask;
    }

    public Task<List<HistoryEntry>> GetHistoryAsync(string sessionId, int limit = 10)
    {
        return Task.FromResult(new List<HistoryEntry>());
    }

    public string GetExportUrl(string sessionId, string format)
    {
        return "#";
    }
}
