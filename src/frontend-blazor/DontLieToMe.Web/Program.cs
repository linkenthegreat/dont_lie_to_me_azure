using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using Blazored.LocalStorage;
using DontLieToMe.Web;
using DontLieToMe.Web.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

var configuredApiBase = builder.Configuration["ApiBaseUrl"];
var apiBase = BuildApiBaseUri(builder.HostEnvironment.BaseAddress, configuredApiBase);
var useMock = builder.Configuration["UseMockApi"] ?? "false";

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = apiBase });

if (useMock == "true")
    builder.Services.AddScoped<IApiClient, MockApiClient>();
else
    builder.Services.AddScoped<IApiClient, ApiClient>();

builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IConversationStorageService, ConversationStorageService>();
builder.Services.AddScoped<AppState>();
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddFluentUIComponents();

await builder.Build().RunAsync();

static Uri BuildApiBaseUri(string hostBaseAddress, string? configuredApiBase)
{
    var hostBaseUri = new Uri(hostBaseAddress, UriKind.Absolute);

    if (string.IsNullOrWhiteSpace(configuredApiBase))
    {
        return new Uri(hostBaseUri, "api/");
    }

    if (Uri.TryCreate(configuredApiBase, UriKind.Absolute, out var absoluteUri))
    {
        return EnsureUriTrailingSlash(absoluteUri);
    }

    var relativePath = configuredApiBase.TrimStart('/');
    return new Uri(hostBaseUri, EnsurePathTrailingSlash(relativePath));
}

static Uri EnsureUriTrailingSlash(Uri uri)
{
    return uri.AbsoluteUri.EndsWith("/") ? uri : new Uri(uri.AbsoluteUri + "/");
}

static string EnsurePathTrailingSlash(string path)
{
    return path.EndsWith("/") ? path : path + "/";
}
