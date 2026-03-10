using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using Blazored.LocalStorage;
using DontLieToMe.Web;
using DontLieToMe.Web.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

var apiBase = builder.Configuration["ApiBaseUrl"] ?? "http://localhost:7071/api";
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(apiBase) });

builder.Services.AddScoped<IApiClient, ApiClient>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<AppState>();
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddFluentUIComponents();

await builder.Build().RunAsync();
