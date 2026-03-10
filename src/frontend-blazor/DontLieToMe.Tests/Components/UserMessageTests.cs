using Bunit;
using DontLieToMe.Web.Components.Chat;
using DontLieToMe.Web.Models;

namespace DontLieToMe.Tests.Components;

public class UserMessageTests : TestContext
{
    [Fact]
    public void Renders_MessageContent()
    {
        var message = new ChatMessage
        {
            Role = "user",
            Content = "Is this a scam?",
            Timestamp = new DateTime(2026, 3, 10, 14, 30, 0, DateTimeKind.Utc)
        };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        Assert.Contains("Is this a scam?", cut.Markup);
    }

    [Fact]
    public void Renders_Timestamp()
    {
        var message = new ChatMessage
        {
            Role = "user",
            Content = "test",
            Timestamp = new DateTime(2026, 3, 10, 14, 30, 0, DateTimeKind.Utc)
        };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        Assert.Contains("14:30", cut.Markup);
    }

    [Fact]
    public void Renders_UserBubbleClasses()
    {
        var message = new ChatMessage { Role = "user", Content = "test" };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        Assert.Contains("msg--user", cut.Markup);
        Assert.Contains("msg__bubble--user", cut.Markup);
    }

    [Fact]
    public void Renders_Images_WhenPresent()
    {
        var message = new ChatMessage
        {
            Role = "user",
            Content = "Check this",
            Images = new List<string>
            {
                "data:image/png;base64,abc",
                "data:image/jpeg;base64,def"
            }
        };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        var images = cut.FindAll(".msg__img");
        Assert.Equal(2, images.Count);
    }

    [Fact]
    public void NoImages_DoesNotRenderImageContainer()
    {
        var message = new ChatMessage { Role = "user", Content = "text only" };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        Assert.Empty(cut.FindAll(".msg__images"));
    }

    [Fact]
    public void HasListItemRole()
    {
        var message = new ChatMessage { Role = "user", Content = "test" };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        Assert.Contains("role=\"listitem\"", cut.Markup);
    }

    [Fact]
    public void Images_HaveLazyLoading()
    {
        var message = new ChatMessage
        {
            Role = "user",
            Content = "image",
            Images = new List<string> { "data:image/png;base64,abc" }
        };

        var cut = RenderComponent<UserMessage>(p =>
            p.Add(c => c.Message, message));

        Assert.Contains("loading=\"lazy\"", cut.Markup);
    }
}
