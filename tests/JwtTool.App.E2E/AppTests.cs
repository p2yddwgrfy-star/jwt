using System.Text.RegularExpressions;
using Microsoft.Playwright;
using Xunit;

namespace JwtTool.App.E2E;

[Collection("App")]
public sealed class AppTests(AppFixture fixture)
{
    // Canonical jwt.io token signed with "your-256-bit-secret".
    private const string CanonicalToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string CanonicalSecret = "your-256-bit-secret";

    private const string CanonicalPayloadJson = """{"sub":"1234567890","name":"John Doe","iat":1516239022}""";

    /// <summary>A fresh page, waited until Blazor has actually rendered the app shell.</summary>
    private async Task<IPage> OpenAppAsync()
    {
        var page = await fixture.OpenPageAsync();
        // The boot spinner lives elsewhere; the app title only exists once WASM rendered.
        await page.WaitForSelectorAsync(".app-title");
        return page;
    }

    [Fact]
    public async Task Decode_shows_colored_parts_and_decoded_json()
    {
        var page = await OpenAppAsync();

        await page.Locator("#token-box").FillAsync(CanonicalToken);

        // Encoded view: the token is rendered as three color-coded spans.
        await Assertions.Expect(page.Locator(".two-pane p span.part")).ToHaveCountAsync(3);

        // Decoded view: pretty-printed JSON and the time-claim table.
        await Assertions.Expect(page.Locator("pre.header-part")).ToContainTextAsync("HS256");
        await Assertions.Expect(page.Locator("pre.payload-part")).ToContainTextAsync("John Doe");
        await Assertions.Expect(page.Locator("table")).ToContainTextAsync("iat");
        await Assertions.Expect(page.Locator(".warnings")).ToHaveCountAsync(0);
    }

    [Fact]
    public async Task Decode_a_garbage_input_shows_the_not_a_token_error()
    {
        var page = await OpenAppAsync();

        await page.Locator("#token-box").FillAsync("this is not a token");

        var error = page.Locator(".parse-error");
        await Assertions.Expect(error).ToBeVisibleAsync();
        // The ParseError is the sole message — no hard-coded lead-in next to it (#21).
        await Assertions.Expect(error).ToContainTextAsync("this input has 1 part(s)");
        await Assertions.Expect(error).Not.ToContainTextAsync("Not a token.");
    }

    [Fact]
    public async Task Verify_with_the_correct_secret_turns_the_verdict_green()
    {
        var page = await OpenAppAsync();

        await page.Locator("#token-box").FillAsync(CanonicalToken);
        await page.Locator("#key-box").FillAsync(CanonicalSecret);

        var verdict = page.Locator(".verdict");
        await Assertions.Expect(verdict).ToContainTextAsync("Valid signature.");
        await Assertions.Expect(verdict).ToHaveClassAsync(new Regex("valid"));
    }

    [Fact]
    public async Task Verify_with_a_wrong_secret_reports_invalid_with_a_reason()
    {
        var page = await OpenAppAsync();

        await page.Locator("#token-box").FillAsync(CanonicalToken);
        await page.Locator("#key-box").FillAsync("not the secret");

        var verdict = page.Locator(".verdict");
        await Assertions.Expect(verdict).ToContainTextAsync("Invalid signature.");
        await Assertions.Expect(verdict).ToContainTextAsync("Signature");
        await Assertions.Expect(verdict).ToHaveClassAsync(new Regex("invalid"));
    }

    [Fact]
    public async Task Encode_tab_signs_a_fresh_token_live()
    {
        var page = await OpenAppAsync();
        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();

        await page.Locator("#enc-header").FillAsync("""{"alg":"HS256","typ":"JWT"}""");
        await page.Locator("#enc-payload").FillAsync("""{"sub":"e2e"}""");
        await page.Locator("#enc-key").FillAsync(CanonicalSecret);

        var output = page.Locator("#encoded-token");
        var token = (await output.TextContentAsync() ?? "").Trim();
        Assert.Equal(3, token.Split('.').Length);

        // The output is color-coded: three part spans inside the pre.
        await Assertions.Expect(output.Locator("span.part")).ToHaveCountAsync(3);
    }

    [Fact]
    public async Task Tab_switching_preserves_the_encode_editors_state()
    {
        var page = await OpenAppAsync();
        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();

        await page.Locator("#enc-payload").FillAsync("""{"sub":"persist-me"}""");
        await page.Locator("#enc-key").FillAsync("persist-secret");

        await page.GetByRole(AriaRole.Tab, new() { Name = "Decode" }).ClickAsync();
        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();

        // The component stays mounted across switches, so nothing resets (#9's regression).
        Assert.Equal("""{"sub":"persist-me"}""", await page.Locator("#enc-payload").InputValueAsync());
        Assert.Equal("persist-secret", await page.Locator("#enc-key").InputValueAsync());
    }

    [Fact]
    public async Task Tweak_and_re_encode_populates_the_encode_editors_from_the_decoded_token()
    {
        var page = await OpenAppAsync();

        await page.Locator("#token-box").FillAsync(CanonicalToken);
        await page.GetByRole(AriaRole.Button, new() { Name = "Tweak & re-encode" }).ClickAsync();

        // The Encode tab is now active and carries the decoded token's JSON (#9's crash flow).
        var payload = await page.Locator("#enc-payload").InputValueAsync();
        Assert.Equal(Compact(CanonicalPayloadJson), Compact(payload));

        await page.Locator("#enc-key").FillAsync(CanonicalSecret);
        var token = (await page.Locator("#encoded-token").TextContentAsync() ?? "").Trim();
        Assert.Equal(3, token.Split('.').Length);
    }

    [Fact]
    public async Task Copy_JSON_shows_copied_and_lands_the_text_on_the_clipboard()
    {
        var page = await OpenAppAsync();
        // With permission granted, the success path must run — the old either-outcome
        // assertion passed even if "Copied." could never render (#24).
        await page.Context.GrantPermissionsAsync(["clipboard-read", "clipboard-write"]);

        await page.Locator("#token-box").FillAsync(CanonicalToken);
        await page.GetByRole(AriaRole.Button, new() { Name = "Copy JSON" }).ClickAsync();

        await Assertions.Expect(page.Locator(".copy-status")).ToContainTextAsync("Copied.");

        // And the copy is real: header + payload JSON, not a silent no-op.
        var clipboard = await page.EvaluateAsync<string>("() => navigator.clipboard.readText()");
        Assert.Contains("HS256", clipboard);
        Assert.Contains("John Doe", clipboard);
    }

    [Fact]
    public async Task Copy_shows_the_failure_hint_when_the_clipboard_is_blocked()
    {
        var page = await OpenAppAsync();

        // Simulate a browser that denies clipboard writes, so the catch branch in
        // Clipboard.CopyAsync runs deterministically instead of depending on
        // headless permission defaults.
        await page.AddInitScriptAsync("""
            Object.defineProperty(navigator, 'clipboard', {
                value: { writeText: () => Promise.reject(new DOMException('denied', 'NotAllowedError')) }
            });
        """);
        await page.ReloadAsync();
        await page.WaitForSelectorAsync(".app-title");

        await page.Locator("#token-box").FillAsync(CanonicalToken);
        await page.GetByRole(AriaRole.Button, new() { Name = "Copy JSON" }).ClickAsync();

        await Assertions.Expect(page.Locator(".copy-status")).ToContainTextAsync("Copy failed");
    }

    /// <summary>Strips whitespace so a pretty-printed editor value compares equal to compact JSON.</summary>
    private static string Compact(string json) =>
        Regex.Replace(json, @"\s+", "");
}
