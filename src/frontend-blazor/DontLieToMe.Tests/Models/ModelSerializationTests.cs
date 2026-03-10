using System.Text.Json;
using DontLieToMe.Web.Models;

namespace DontLieToMe.Tests.Models;

public class ModelSerializationTests
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    [Fact]
    public void ChatRequest_SerializesToSnakeCase()
    {
        var request = new ChatRequest
        {
            Message = "Is this a scam?",
            SessionId = "abc-123",
            Images = new List<string> { "data:image/png;base64,test" },
            Context = new ChatContext
            {
                Location = "AU",
                ConversationHistory = new List<ConversationMessage>
                {
                    new() { Role = "user", Content = "hello" }
                }
            }
        };

        var json = JsonSerializer.Serialize(request);

        Assert.Contains("\"message\"", json);
        Assert.Contains("\"session_id\"", json);
        Assert.Contains("\"images\"", json);
        Assert.Contains("\"context\"", json);
        Assert.Contains("\"location\"", json);
        Assert.Contains("\"conversation_history\"", json);
    }

    [Fact]
    public void ChatResponse_DeserializesFromBackendJson()
    {
        var json = """
        {
            "message": "This looks like a scam.",
            "data": {
                "classification": "SCAM",
                "confidence": 0.95,
                "reasoning": "Urgency language detected"
            },
            "agent_used": "classifier",
            "trace": {
                "route_path": ["orchestrator", "classifier"],
                "routing_decision": "suspicious_content",
                "duration_ms": 345.2,
                "model_used": "gpt-4o",
                "timestamp": "2026-03-10T12:00:00Z",
                "fallback_triggered": false
            },
            "session_id": "session-xyz"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("This looks like a scam.", response!.Message);
        Assert.Equal("classifier", response.AgentUsed);
        Assert.Equal("session-xyz", response.SessionId);
        Assert.Null(response.Error);

        Assert.NotNull(response.Data);
        Assert.True(response.Data!.ContainsKey("classification"));
        Assert.Equal("SCAM", response.Data["classification"].GetString());
        Assert.Equal(0.95, response.Data["confidence"].GetDouble(), 2);

        Assert.NotNull(response.Trace);
        Assert.Equal(2, response.Trace!.RoutePath!.Count);
        Assert.Equal("orchestrator", response.Trace.RoutePath[0]);
        Assert.Equal(345.2, response.Trace.DurationMs);
        Assert.False(response.Trace.FallbackTriggered);
    }

    [Fact]
    public void ChatResponse_DeserializesUrlAnalysis()
    {
        var json = """
        {
            "message": "This URL is suspicious.",
            "data": {
                "verdict": "SUSPICIOUS",
                "risk_score": 0.7,
                "url": "http://example-phish.tk/login",
                "threats": ["Suspicious TLD", "No HTTPS"]
            },
            "agent_used": "url_analyzer"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("url_analyzer", response!.AgentUsed);
        Assert.NotNull(response.Data);
        Assert.Equal("SUSPICIOUS", response.Data!["verdict"].GetString());
        Assert.Equal(0.7, response.Data["risk_score"].GetDouble(), 1);
    }

    [Fact]
    public void ChatResponse_DeserializesImageAnalysis()
    {
        var json = """
        {
            "message": "The image shows signs of manipulation.",
            "data": {
                "authenticity_score": 0.35,
                "verdict": "LIKELY_MANIPULATED",
                "manipulation_indicators": [
                    {"type": "text_editing", "description": "Font mismatch", "confidence": 0.8}
                ],
                "summary": "Signs of text editing detected"
            },
            "agent_used": "image_analyzer"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("image_analyzer", response!.AgentUsed);
        Assert.Equal(0.35, response.Data!["authenticity_score"].GetDouble(), 2);
        Assert.Equal("LIKELY_MANIPULATED", response.Data["verdict"].GetString());
    }

    [Fact]
    public void ChatResponse_DeserializesSentimentAnalysis()
    {
        var json = """
        {
            "message": "High pressure detected.",
            "data": {
                "sentiment": {
                    "primary_emotion": "urgency",
                    "overall_tone": "threatening"
                },
                "manipulation": {
                    "pressure_score": 0.9,
                    "techniques_detected": ["Fear appeal", "Authority"]
                },
                "risk_assessment": "HIGH"
            },
            "agent_used": "sentiment_analyzer"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        Assert.NotNull(response!.Data);
        Assert.True(response.Data!.ContainsKey("sentiment"));
        Assert.True(response.Data.ContainsKey("manipulation"));
        Assert.Equal("HIGH", response.Data["risk_assessment"].GetString());
    }

    [Fact]
    public void ChatResponse_DeserializesGuidance()
    {
        var json = """
        {
            "message": "Here's what you should do.",
            "data": {
                "immediate_actions": ["Do not click links", "Block sender"],
                "reporting_steps": ["Report to Scamwatch"],
                "prevention_tips": ["Verify via official channels"],
                "resources": ["https://www.scamwatch.gov.au/"]
            },
            "agent_used": "guidance"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        var actions = response!.Data!["immediate_actions"];
        Assert.Equal(JsonValueKind.Array, actions.ValueKind);
        Assert.Equal(2, actions.GetArrayLength());
    }

    [Fact]
    public void ChatResponse_HandlesNullData()
    {
        var json = """
        {
            "message": "Hello! How can I help?",
            "agent_used": "receptionist"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        Assert.Null(response!.Data);
        Assert.Null(response.Trace);
        Assert.Null(response.Error);
    }

    [Fact]
    public void ChatResponse_HandlesErrorField()
    {
        var json = """
        {
            "message": "",
            "error": "Internal server error"
        }
        """;

        var response = JsonSerializer.Deserialize<ChatResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("Internal server error", response!.Error);
    }

    [Fact]
    public void OrchestrationTrace_DeserializesComplete()
    {
        var json = """
        {
            "route_path": ["orchestrator", "classifier", "analyzer", "guidance"],
            "routing_decision": "suspicious_content_chain",
            "duration_ms": 1234.5,
            "model_used": "gpt-4o",
            "timestamp": "2026-03-10T12:00:00Z",
            "fallback_triggered": true
        }
        """;

        var trace = JsonSerializer.Deserialize<OrchestrationTrace>(json);

        Assert.NotNull(trace);
        Assert.Equal(4, trace!.RoutePath!.Count);
        Assert.Equal("suspicious_content_chain", trace.RoutingDecision);
        Assert.Equal(1234.5, trace.DurationMs);
        Assert.Equal("gpt-4o", trace.ModelUsed);
        Assert.True(trace.FallbackTriggered);
    }

    [Fact]
    public void HistoryEntry_DeserializesFromBackend()
    {
        var json = """
        {
            "id": "entry-1",
            "sessionId": "sess-abc",
            "endpoint": "chat",
            "inputText": "Is this a scam?",
            "result": {"classification": "SCAM"},
            "timestamp": "2026-03-10T12:00:00Z"
        }
        """;

        var entry = JsonSerializer.Deserialize<HistoryEntry>(json);

        Assert.NotNull(entry);
        Assert.Equal("entry-1", entry!.Id);
        Assert.Equal("sess-abc", entry.SessionId);
        Assert.Equal("chat", entry.Endpoint);
        Assert.NotNull(entry.Result);
    }

    [Fact]
    public void FeedbackRequest_SerializesCorrectly()
    {
        var feedback = new FeedbackRequest
        {
            Rating = 1,
            SessionId = "sess-abc"
        };

        var json = JsonSerializer.Serialize(feedback);

        Assert.Contains("\"rating\"", json);
        Assert.Contains("\"session_id\"", json);
        Assert.Contains("1", json);
    }

    [Fact]
    public void ChatContext_SerializesWithHistory()
    {
        var context = new ChatContext
        {
            Location = "AU",
            Role = "consumer",
            ConversationHistory = new List<ConversationMessage>
            {
                new() { Role = "user", Content = "Hello" },
                new() { Role = "assistant", Content = "Hi there!" }
            }
        };

        var json = JsonSerializer.Serialize(context);

        Assert.Contains("\"location\"", json);
        Assert.Contains("\"AU\"", json);
        Assert.Contains("\"conversation_history\"", json);
        Assert.Contains("\"role\"", json);
    }
}
