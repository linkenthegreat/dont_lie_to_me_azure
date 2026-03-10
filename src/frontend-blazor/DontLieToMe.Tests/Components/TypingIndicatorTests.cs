using Bunit;
using DontLieToMe.Web.Components.Chat;

namespace DontLieToMe.Tests.Components;

public class TypingIndicatorTests : TestContext
{
    [Fact]
    public void Renders_ThreeDots()
    {
        var cut = RenderComponent<TypingIndicator>();

        var dots = cut.FindAll(".typing__dot");
        Assert.Equal(3, dots.Count);
    }

    [Fact]
    public void HasAccessibilityAttributes()
    {
        var cut = RenderComponent<TypingIndicator>();

        Assert.Contains("role=\"status\"", cut.Markup);
        Assert.Contains("Analyzing...", cut.Markup);
    }

    [Fact]
    public void UsesAssistantBubbleStyle()
    {
        var cut = RenderComponent<TypingIndicator>();

        Assert.Contains("msg--assistant", cut.Markup);
        Assert.Contains("msg__bubble--assistant", cut.Markup);
    }
}
