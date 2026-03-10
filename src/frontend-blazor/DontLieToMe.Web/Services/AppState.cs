using DontLieToMe.Web.Models;

namespace DontLieToMe.Web.Services;

public class AppState
{
    private const int MaxDisplayMessages = 50;
    private const int MaxContextMessages = 6;

    public List<ChatMessage> Messages { get; private set; } = new();
    public List<string> CurrentImages { get; private set; } = new();
    public bool IsLoading { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string CurrentConversationId { get; private set; } = Guid.NewGuid().ToString();

    public event Action? OnChange;

    public void AddUserMessage(string content, List<string>? images = null)
    {
        Messages.Add(new ChatMessage
        {
            Role = "user",
            Content = content,
            Images = images?.Count > 0 ? new List<string>(images) : null,
            Timestamp = DateTime.UtcNow
        });

        if (Messages.Count > MaxDisplayMessages)
            Messages.RemoveAt(0);

        ClearImages();
        NotifyStateChanged();
    }

    public void AddAssistantMessage(ChatResponse response)
    {
        Messages.Add(new ChatMessage
        {
            Role = "assistant",
            Content = response.Message,
            Timestamp = DateTime.UtcNow,
            Response = response
        });

        if (Messages.Count > MaxDisplayMessages)
            Messages.RemoveAt(0);

        NotifyStateChanged();
    }

    public List<ConversationMessage> GetConversationHistory()
    {
        return Messages
            .TakeLast(MaxContextMessages)
            .Select(m => new ConversationMessage { Role = m.Role, Content = m.Content })
            .ToList();
    }

    public void AddImage(string base64DataUri)
    {
        CurrentImages.Add(base64DataUri);
        NotifyStateChanged();
    }

    public void RemoveImage(int index)
    {
        if (index >= 0 && index < CurrentImages.Count)
        {
            CurrentImages.RemoveAt(index);
            NotifyStateChanged();
        }
    }

    public void ClearImages()
    {
        CurrentImages.Clear();
    }

    public void SetLoading(bool loading)
    {
        IsLoading = loading;
        NotifyStateChanged();
    }

    public void SetError(string? error)
    {
        ErrorMessage = error;
        NotifyStateChanged();
    }

    public void StartNewConversation()
    {
        Messages.Clear();
        ClearImages();
        ClearError();
        CurrentConversationId = Guid.NewGuid().ToString();
        NotifyStateChanged();
    }

    public void LoadConversation(Conversation conversation)
    {
        CurrentConversationId = conversation.Id;
        Messages = new List<ChatMessage>(conversation.Messages);
        ClearImages();
        ClearError();
        NotifyStateChanged();
    }

    public Conversation ToConversation()
    {
        var title = Messages.FirstOrDefault(m => m.Role == "user")?.Content ?? "New conversation";
        if (title.Length > 60) title = title[..60] + "...";

        return new Conversation
        {
            Id = CurrentConversationId,
            Title = title,
            Messages = new List<ChatMessage>(Messages),
            UpdatedAt = DateTime.UtcNow
        };
    }

    public void ClearMessages()
    {
        Messages.Clear();
        ClearImages();
        ClearError();
        NotifyStateChanged();
    }

    public void ClearError()
    {
        ErrorMessage = null;
        NotifyStateChanged();
    }

    private void NotifyStateChanged() => OnChange?.Invoke();
}
