using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DontLieToMe.Web.Models;
using DontLieToMe.Web.Services;

namespace DontLieToMe.Tests.Services;

public class ApiClientTests
{
    private static HttpClient CreateMockHttpClient(HttpMessageHandler handler)
    {
        return new HttpClient(handler) { BaseAddress = new Uri("http://localhost:7071/api/") };
    }

    [Fact]
    public async Task SendChatMessageAsync_Success_ReturnsResponse()
    {
        var expected = new ChatResponse
        {
            Message = "This is a scam",
            AgentUsed = "classifier",
            SessionId = "test-session",
            Data = new Dictionary<string, JsonElement>
            {
                ["classification"] = JsonSerializer.SerializeToElement("SCAM"),
                ["confidence"] = JsonSerializer.SerializeToElement(0.95)
            },
            Trace = new OrchestrationTrace
            {
                RoutePath = new List<string> { "orchestrator", "classifier" },
                DurationMs = 234.5
            }
        };

        var handler = new MockHttpHandler(HttpStatusCode.OK, expected);
        var client = new ApiClient(CreateMockHttpClient(handler));

        var request = new ChatRequest
        {
            Message = "Is this a scam?",
            SessionId = "test-session"
        };

        var result = await client.SendChatMessageAsync(request);

        Assert.Equal("This is a scam", result.Message);
        Assert.Equal("classifier", result.AgentUsed);
        Assert.NotNull(result.Data);
        Assert.True(result.Data!.ContainsKey("classification"));
        Assert.NotNull(result.Trace);
        Assert.Equal(2, result.Trace!.RoutePath!.Count);
    }

    [Fact]
    public async Task SendChatMessageAsync_ServerError_ReturnsErrorResponse()
    {
        var handler = new MockHttpHandler(HttpStatusCode.InternalServerError);
        var client = new ApiClient(CreateMockHttpClient(handler));

        var request = new ChatRequest { Message = "test" };
        var result = await client.SendChatMessageAsync(request);

        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task SendChatMessageAsync_NetworkError_ReturnsErrorResponse()
    {
        var handler = new MockHttpHandler(new HttpRequestException("Connection refused"));
        var client = new ApiClient(CreateMockHttpClient(handler));

        var request = new ChatRequest { Message = "test" };
        var result = await client.SendChatMessageAsync(request);

        Assert.NotNull(result.Error);
        Assert.Contains("Connection refused", result.Error);
    }

    [Fact]
    public async Task SendChatMessageAsync_WithImages_SendsCorrectPayload()
    {
        var handler = new MockHttpHandler(HttpStatusCode.OK, new ChatResponse { Message = "Image analyzed" });
        var client = new ApiClient(CreateMockHttpClient(handler));

        var request = new ChatRequest
        {
            Message = "Check this image",
            Images = new List<string> { "data:image/png;base64,abc123" },
            SessionId = "s1",
            Context = new ChatContext
            {
                Location = "AU",
                ConversationHistory = new List<ConversationMessage>
                {
                    new() { Role = "user", Content = "previous message" }
                }
            }
        };

        var result = await client.SendChatMessageAsync(request);

        Assert.Equal("Image analyzed", result.Message);
        Assert.NotNull(handler.LastRequestContent);
        Assert.Contains("abc123", handler.LastRequestContent);
    }

    [Fact]
    public async Task GetHistoryAsync_Success_ReturnsList()
    {
        var entries = new List<HistoryEntry>
        {
            new() { Id = "1", Endpoint = "chat", InputText = "test", Timestamp = "2026-03-10T00:00:00Z" },
            new() { Id = "2", Endpoint = "chat", InputText = "test2", Timestamp = "2026-03-10T01:00:00Z" }
        };

        var handler = new MockHttpHandler(HttpStatusCode.OK, entries);
        var client = new ApiClient(CreateMockHttpClient(handler));

        var result = await client.GetHistoryAsync("session-1", 10);

        Assert.Equal(2, result.Count);
    }

    [Fact]
    public async Task GetHistoryAsync_Error_ReturnsEmptyList()
    {
        var handler = new MockHttpHandler(new HttpRequestException("fail"));
        var client = new ApiClient(CreateMockHttpClient(handler));

        var result = await client.GetHistoryAsync("session-1");

        Assert.Empty(result);
    }

    [Fact]
    public void GetExportUrl_ReturnsCorrectFormat()
    {
        var handler = new MockHttpHandler(HttpStatusCode.OK, new ChatResponse());
        var client = new ApiClient(CreateMockHttpClient(handler));

        var url = client.GetExportUrl("session-123", "csv");

        Assert.Equal("http://localhost:7071/api/export?session_id=session-123&format=csv", url);
    }

    [Fact]
    public void GetExportUrl_PdfFormat()
    {
        var handler = new MockHttpHandler(HttpStatusCode.OK, new ChatResponse());
        var client = new ApiClient(CreateMockHttpClient(handler));

        var url = client.GetExportUrl("s1", "pdf");

        Assert.Contains("format=pdf", url);
    }
}

/// <summary>
/// Mock HttpMessageHandler for testing ApiClient without real HTTP calls.
/// </summary>
public class MockHttpHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly object? _responseBody;
    private readonly Exception? _exception;

    public string? LastRequestContent { get; private set; }
    public string? LastRequestUri { get; private set; }

    public MockHttpHandler(HttpStatusCode statusCode, object? responseBody = null)
    {
        _statusCode = statusCode;
        _responseBody = responseBody;
    }

    public MockHttpHandler(Exception exception)
    {
        _exception = exception;
        _statusCode = HttpStatusCode.OK;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_exception is not null)
            throw _exception;

        LastRequestUri = request.RequestUri?.ToString();
        if (request.Content is not null)
            LastRequestContent = await request.Content.ReadAsStringAsync(cancellationToken);

        var response = new HttpResponseMessage(_statusCode);
        if (_responseBody is not null)
        {
            response.Content = new StringContent(
                JsonSerializer.Serialize(_responseBody),
                System.Text.Encoding.UTF8,
                "application/json");
        }
        return response;
    }
}
