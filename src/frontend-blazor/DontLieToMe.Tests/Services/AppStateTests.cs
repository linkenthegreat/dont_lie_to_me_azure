using System.Text.Json;
using DontLieToMe.Web.Models;
using DontLieToMe.Web.Services;

namespace DontLieToMe.Tests.Services;

public class AppStateTests
{
    private readonly AppState _state = new();

    [Fact]
    public void AddUserMessage_AddsToMessages()
    {
        _state.AddUserMessage("Hello");

        Assert.Single(_state.Messages);
        Assert.Equal("user", _state.Messages[0].Role);
        Assert.Equal("Hello", _state.Messages[0].Content);
    }

    [Fact]
    public void AddUserMessage_WithImages_StoresImages()
    {
        var images = new List<string> { "data:image/png;base64,abc123" };

        _state.AddUserMessage("Check this", images);

        Assert.Single(_state.Messages);
        Assert.NotNull(_state.Messages[0].Images);
        Assert.Single(_state.Messages[0].Images!);
    }

    [Fact]
    public void AddUserMessage_ClearsCurrentImages()
    {
        _state.AddImage("data:image/png;base64,abc");
        Assert.Single(_state.CurrentImages);

        _state.AddUserMessage("Send");

        Assert.Empty(_state.CurrentImages);
    }

    [Fact]
    public void AddAssistantMessage_StoresResponseData()
    {
        var response = new ChatResponse
        {
            Message = "This looks suspicious",
            AgentUsed = "classifier",
            Data = new Dictionary<string, JsonElement>
            {
                ["classification"] = JsonSerializer.SerializeToElement("SCAM")
            }
        };

        _state.AddAssistantMessage(response);

        Assert.Single(_state.Messages);
        Assert.Equal("assistant", _state.Messages[0].Role);
        Assert.NotNull(_state.Messages[0].Response);
        Assert.Equal("classifier", _state.Messages[0].Response!.AgentUsed);
    }

    [Fact]
    public void Messages_CappedAt50()
    {
        for (int i = 0; i < 55; i++)
            _state.AddUserMessage($"Message {i}");

        Assert.Equal(50, _state.Messages.Count);
        Assert.Equal("Message 5", _state.Messages[0].Content);
    }

    [Fact]
    public void GetConversationHistory_ReturnsLast6Messages()
    {
        for (int i = 0; i < 10; i++)
            _state.AddUserMessage($"Msg {i}");

        var history = _state.GetConversationHistory();

        Assert.Equal(6, history.Count);
        Assert.Equal("Msg 4", history[0].Content);
        Assert.Equal("Msg 9", history[5].Content);
    }

    [Fact]
    public void GetConversationHistory_ReturnsAllWhenLessThan6()
    {
        _state.AddUserMessage("First");
        _state.AddUserMessage("Second");

        var history = _state.GetConversationHistory();

        Assert.Equal(2, history.Count);
    }

    [Fact]
    public void AddImage_AddsToCurrentImages()
    {
        _state.AddImage("data:image/png;base64,img1");
        _state.AddImage("data:image/png;base64,img2");

        Assert.Equal(2, _state.CurrentImages.Count);
    }

    [Fact]
    public void RemoveImage_RemovesAtIndex()
    {
        _state.AddImage("img0");
        _state.AddImage("img1");
        _state.AddImage("img2");

        _state.RemoveImage(1);

        Assert.Equal(2, _state.CurrentImages.Count);
        Assert.Equal("img0", _state.CurrentImages[0]);
        Assert.Equal("img2", _state.CurrentImages[1]);
    }

    [Fact]
    public void RemoveImage_InvalidIndex_DoesNothing()
    {
        _state.AddImage("img0");

        _state.RemoveImage(-1);
        _state.RemoveImage(5);

        Assert.Single(_state.CurrentImages);
    }

    [Fact]
    public void SetLoading_UpdatesState()
    {
        Assert.False(_state.IsLoading);

        _state.SetLoading(true);
        Assert.True(_state.IsLoading);

        _state.SetLoading(false);
        Assert.False(_state.IsLoading);
    }

    [Fact]
    public void SetError_And_ClearError()
    {
        _state.SetError("Network error");
        Assert.Equal("Network error", _state.ErrorMessage);

        _state.ClearError();
        Assert.Null(_state.ErrorMessage);
    }

    [Fact]
    public void OnChange_FiresOnStateChange()
    {
        int changeCount = 0;
        _state.OnChange += () => changeCount++;

        _state.AddUserMessage("test");
        _state.SetLoading(true);
        _state.SetError("err");
        _state.ClearError();
        _state.AddImage("img");
        _state.RemoveImage(0);

        Assert.Equal(6, changeCount);
    }

    [Fact]
    public void AddUserMessage_SetsTimestamp()
    {
        var before = DateTime.UtcNow;
        _state.AddUserMessage("test");
        var after = DateTime.UtcNow;

        Assert.InRange(_state.Messages[0].Timestamp, before, after);
    }

    [Fact]
    public void AddUserMessage_NullImages_StoresNull()
    {
        _state.AddUserMessage("no images", null);

        Assert.Null(_state.Messages[0].Images);
    }

    [Fact]
    public void AddUserMessage_EmptyImages_StoresNull()
    {
        _state.AddUserMessage("no images", new List<string>());

        Assert.Null(_state.Messages[0].Images);
    }
}
