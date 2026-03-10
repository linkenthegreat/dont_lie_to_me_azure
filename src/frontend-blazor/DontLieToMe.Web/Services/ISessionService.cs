namespace DontLieToMe.Web.Services;

public interface ISessionService
{
    Task<string> GetSessionIdAsync();
}
