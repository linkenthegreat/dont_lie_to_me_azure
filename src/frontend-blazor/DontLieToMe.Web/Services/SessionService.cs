using Blazored.LocalStorage;

namespace DontLieToMe.Web.Services;

public class SessionService : ISessionService
{
    private readonly ILocalStorageService _localStorage;
    private string? _cachedSessionId;
    private const string StorageKey = "dltm_session_id";

    public SessionService(ILocalStorageService localStorage)
    {
        _localStorage = localStorage;
    }

    public async Task<string> GetSessionIdAsync()
    {
        if (_cachedSessionId is not null)
            return _cachedSessionId;

        _cachedSessionId = await _localStorage.GetItemAsStringAsync(StorageKey);
        if (string.IsNullOrEmpty(_cachedSessionId))
        {
            _cachedSessionId = Guid.NewGuid().ToString();
            await _localStorage.SetItemAsStringAsync(StorageKey, _cachedSessionId);
        }
        return _cachedSessionId;
    }
}
