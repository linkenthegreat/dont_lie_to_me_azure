using Blazored.LocalStorage;
using DontLieToMe.Web.Models;

namespace DontLieToMe.Web.Services;

public interface IConversationStorageService
{
    Task<List<Conversation>> GetConversationsAsync();
    Task<Conversation?> GetConversationAsync(string id);
    Task SaveConversationAsync(Conversation conversation);
    Task DeleteConversationAsync(string id);
}

public class ConversationStorageService : IConversationStorageService
{
    private const string StorageKey = "dltm_conversations";
    private const int MaxConversations = 10;
    private readonly ILocalStorageService _storage;

    public ConversationStorageService(ILocalStorageService storage)
    {
        _storage = storage;
    }

    public async Task<List<Conversation>> GetConversationsAsync()
    {
        try
        {
            var conversations = await _storage.GetItemAsync<List<Conversation>>(StorageKey);
            return conversations ?? new();
        }
        catch
        {
            return new();
        }
    }

    public async Task<Conversation?> GetConversationAsync(string id)
    {
        var conversations = await GetConversationsAsync();
        return conversations.FirstOrDefault(c => c.Id == id);
    }

    public async Task SaveConversationAsync(Conversation conversation)
    {
        var conversations = await GetConversationsAsync();

        var existing = conversations.FindIndex(c => c.Id == conversation.Id);
        if (existing >= 0)
            conversations[existing] = conversation;
        else
            conversations.Insert(0, conversation);

        // Keep only the last N conversations
        if (conversations.Count > MaxConversations)
            conversations = conversations.OrderByDescending(c => c.UpdatedAt).Take(MaxConversations).ToList();

        await _storage.SetItemAsync(StorageKey, conversations);
    }

    public async Task DeleteConversationAsync(string id)
    {
        var conversations = await GetConversationsAsync();
        conversations.RemoveAll(c => c.Id == id);
        await _storage.SetItemAsync(StorageKey, conversations);
    }
}
