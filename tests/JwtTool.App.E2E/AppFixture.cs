using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Playwright;
using Xunit;

namespace JwtTool.App.E2E;

/// <summary>
/// Spawns the real Blazor WASM app (dotnet run) on a free port with the
/// /jwt pathbase — the same shape GitHub Pages serves — and hands out
/// freshly-loaded Chromium pages to each test.
/// </summary>
public sealed class AppFixture : IAsyncLifetime
{
    private readonly List<IBrowser> _browsers = [];
    private Process? _app;
    private IPlaywright? _playwright;
    private int _port;

    public string BaseUrl { get; private set; } = "";

    public async Task InitializeAsync()
    {
        _port = GetFreePort();
        BaseUrl = $"http://127.0.0.1:{_port}";

        var repoRoot = FindRepoRoot();
        var project = Path.Combine(repoRoot, "src", "JwtTool.App");

        _app = Process.Start(new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{project}\" --no-build " +
                        $"--urls {BaseUrl} -- --pathbase=/jwt",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        });
        _app!.OutputDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine(e.Data); };
        _app.ErrorDataReceived += (_, e) => { if (e.Data is not null) Console.Error.WriteLine(e.Data); };
        _app.BeginOutputReadLine();
        _app.BeginErrorReadLine();

        // WASM apps take several seconds to boot; poll until the page shell answers.
        using var http = new HttpClient();
        var deadline = DateTime.UtcNow.AddSeconds(120);
        while (DateTime.UtcNow < deadline)
        {
            if (_app.HasExited)
                throw new InvalidOperationException(
                    $"App exited early with code {_app.ExitCode}. See test output for logs.");
            try
            {
                using var resp = await http.GetAsync($"{BaseUrl}/jwt/");
                if (resp.IsSuccessStatusCode)
                    break;
            }
            catch (HttpRequestException) { /* not up yet */ }
            await Task.Delay(500);
        }

        _playwright = await Playwright.CreateAsync();
    }

    public async Task DisposeAsync()
    {
        foreach (var browser in _browsers)
            await browser.DisposeAsync();
        _playwright?.Dispose();

        if (_app is { HasExited: false })
        {
            _app.Kill(entireProcessTree: true);
            await _app.WaitForExitAsync();
        }
        _app?.Dispose();
    }

    /// <summary>A fresh page in a fresh browser; teardown disposes them all.</summary>
    public async Task<IPage> OpenPageAsync()
    {
        var browser = await _playwright!.Chromium.LaunchAsync();
        _browsers.Add(browser);
        var page = await browser.NewPageAsync();
        await page.GotoAsync($"{BaseUrl}/jwt/", new() { WaitUntil = WaitUntilState.Load });
        return page;
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "JwtTool.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Could not locate JwtTool.slnx upward from the test output directory.");
    }
}

[CollectionDefinition("App")]
public sealed class AppCollection : ICollectionFixture<AppFixture>;
