using Bunit;
using Microsoft.AspNetCore.Components;
using DontLieToMe.Web.Components.Chat;

namespace DontLieToMe.Tests.Components;

public class WelcomeMessageTests : TestContext
{
    [Fact]
    public void Renders_Logo_And_Title()
    {
        var cut = RenderComponent<WelcomeMessage>();

        Assert.Contains("Don't Lie To Me", cut.Markup);
        Assert.Contains("welcome__logo", cut.Markup);
        Assert.Contains("icon-192.png", cut.Markup);
    }

    [Fact]
    public void Renders_Three_HintCards()
    {
        var cut = RenderComponent<WelcomeMessage>();

        var cards = cut.FindAll(".hint-card");
        Assert.Equal(3, cards.Count);
    }

    [Fact]
    public void HintCards_HaveCorrectTitles()
    {
        var cut = RenderComponent<WelcomeMessage>();

        Assert.Contains("Check a suspicious message", cut.Markup);
        Assert.Contains("Verify a URL", cut.Markup);
        Assert.Contains("Get help after a scam", cut.Markup);
    }

    [Fact]
    public void HintCard_Click_InvokesCallback()
    {
        string? receivedMessage = null;
        var cut = RenderComponent<WelcomeMessage>(parameters =>
            parameters.Add(p => p.OnHintClick,
                EventCallback.Factory.Create<string>(this, (string msg) => receivedMessage = msg)));

        var firstCard = cut.Find(".hint-card");
        firstCard.Click();

        Assert.NotNull(receivedMessage);
        Assert.Contains("ATO refund", receivedMessage!);
    }

    [Fact]
    public void UrlHintCard_Click_SendsUrlMessage()
    {
        string? receivedMessage = null;
        var cut = RenderComponent<WelcomeMessage>(parameters =>
            parameters.Add(p => p.OnHintClick,
                EventCallback.Factory.Create<string>(this, (string msg) => receivedMessage = msg)));

        var cards = cut.FindAll(".hint-card");
        cards[1].Click();

        Assert.NotNull(receivedMessage);
        Assert.Contains("suspicious-site.com", receivedMessage!);
    }

    [Fact]
    public void ScamHelpCard_Click_SendsGuidanceMessage()
    {
        string? receivedMessage = null;
        var cut = RenderComponent<WelcomeMessage>(parameters =>
            parameters.Add(p => p.OnHintClick,
                EventCallback.Factory.Create<string>(this, (string msg) => receivedMessage = msg)));

        var cards = cut.FindAll(".hint-card");
        cards[2].Click();

        Assert.NotNull(receivedMessage);
        Assert.Contains("scammed", receivedMessage!);
    }

    [Fact]
    public void HasAccessibilityRole()
    {
        var cut = RenderComponent<WelcomeMessage>();

        var banner = cut.Find("[role='banner']");
        Assert.NotNull(banner);
    }
}
