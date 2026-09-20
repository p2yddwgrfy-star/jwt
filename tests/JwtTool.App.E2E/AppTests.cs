using System.Security.Cryptography;
using System.Text;
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
    public async Task Verify_an_rs256_token_with_a_public_pem_turns_the_verdict_green()
    {
        var page = await OpenAppAsync();
        var (token, matchingPem, foreignPem) = MakeRs256TokenPair();

        await page.Locator("#token-box").FillAsync(token);
        // Scoped to the Decode tab's verify section: the hidden Encode tab
        // has its own .verify-controls select, which strict mode would reject.
        await page.Locator(".verify-section select").SelectOptionAsync("RS256");

        // The key label switched to the PEM wording — the picker actually changed modes.
        await Assertions.Expect(page.Locator(".verify-section .key-label")).ToContainTextAsync("PEM key pair");

        await page.Locator("#key-box").FillAsync(matchingPem);
        var verdict = page.Locator(".verdict");
        await Assertions.Expect(verdict).ToContainTextAsync("Valid signature.");
        await Assertions.Expect(verdict).ToHaveClassAsync(new Regex("valid"));

        // A different key must not verify: the PEM path is real, not a pass-through.
        await page.Locator("#key-box").FillAsync(foreignPem);
        await Assertions.Expect(verdict).ToContainTextAsync("Invalid signature.");
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
    public async Task Encode_tab_signs_rs256_with_a_private_pem_and_the_token_round_trips()
    {
        var page = await OpenAppAsync();
        var consoleErrors = CollectConsoleErrors(page);
        var (privatePem, publicPem) = MakeRs256KeyPair();

        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();
        await page.Locator("#enc-header").FillAsync("""{"alg":"RS256","typ":"JWT"}""");
        // On the Encode tab only one algorithm select is in the tree (the Decode tab's
        // whole section is not rendered, unlike its hidden EncodeTab counterpart).
        await page.Locator(".verify-controls select").SelectOptionAsync("RS256");
        await page.Locator("#enc-key").FillAsync(privatePem);

        var output = page.Locator("#encoded-token");
        await Assertions.Expect(output).ToBeVisibleAsync();
        var token = (await output.TextContentAsync() ?? "").Trim();
        Assert.Equal(3, token.Split('.').Length);

        // Independent check: the browser's signature is standard RS256, verified by the
        // BCL in the test process — not just self-consistent inside Web Crypto.
        var parts = token.Split('.');
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicPem);
        Assert.True(
            rsa.VerifyData(
                Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}"),
                Base64UrlDecode(parts[2]),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1),
            "the browser-signed token does not verify under an independent RS256 implementation");

        // Round-trip inside the app: paste the fresh token into Decode and verify it
        // with the matching public PEM through the Web Crypto verify path.
        await page.GetByRole(AriaRole.Tab, new() { Name = "Decode" }).ClickAsync();
        await page.Locator("#token-box").FillAsync(token);
        await page.Locator(".verify-section select").SelectOptionAsync("RS256");
        await page.Locator("#key-box").FillAsync(publicPem);
        var verdict = page.Locator(".verdict");
        await Assertions.Expect(verdict).ToContainTextAsync("Valid signature.");
        await Assertions.Expect(verdict).ToHaveClassAsync(new Regex("valid"));

        Assert.True(consoleErrors.Count == 0,
            $"Expected no console errors, but got:\n{string.Join("\n", consoleErrors)}");
    }

    [Fact]
    public async Task Encode_tab_handles_crlf_and_untidy_pem_shapes()
    {
        var page = await OpenAppAsync();
        var consoleErrors = CollectConsoleErrors(page);
        var (privatePem, _) = MakeRs256KeyPair();

        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();
        await page.Locator("#enc-header").FillAsync("""{"alg":"RS256","typ":"JWT"}""");
        await page.Locator(".verify-controls select").SelectOptionAsync("RS256");

        await page.Locator("#enc-key").FillAsync(privatePem);
        var output = page.Locator("#encoded-token");
        await Assertions.Expect(output).ToBeVisibleAsync();
        var canonical = (await output.TextContentAsync() ?? "").Trim();

        // Real-world untidy shapes: Windows line endings, surrounding blank lines,
        // trailing spaces, no final newline. The DER bytes must come out identical,
        // so the deterministic RSASSA-PKCS1-v1_5 signature must be identical too.
        var untidy = "\r\n\r\n" + privatePem.Replace("\r\n", "\n").Replace("\n", "\r\n").TrimEnd() + "   \r\n";
        await page.Locator("#enc-key").FillAsync(untidy);
        await Assertions.Expect(output).ToBeVisibleAsync();
        var fromUntidy = (await output.TextContentAsync() ?? "").Trim();

        Assert.Equal(canonical, fromUntidy);
        Assert.True(consoleErrors.Count == 0,
            $"Expected no console errors, but got:\n{string.Join("\n", consoleErrors)}");
    }

    [Fact]
    public async Task Encode_rs256_with_an_unusable_pem_shows_a_friendly_error_and_recovers()
    {
        var page = await OpenAppAsync();
        var consoleErrors = CollectConsoleErrors(page);
        var (privatePem, publicPem) = MakeRs256KeyPair();
        using var encryptedKey = RSA.Create(2048);
        var encryptedPem = PemEncoding.WriteString(
            "ENCRYPTED PRIVATE KEY",
            encryptedKey.ExportEncryptedPkcs8PrivateKey(
                "secret", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000)));

        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();
        await page.Locator("#enc-header").FillAsync("""{"alg":"RS256","typ":"JWT"}""");
        await page.Locator(".verify-controls select").SelectOptionAsync("RS256");

        var error = page.Locator(".parse-error");

        // A public key can verify but never sign: the friendly private-key hint.
        await page.Locator("#enc-key").FillAsync(publicPem);
        await Assertions.Expect(error).ToContainTextAsync("needs the private key");

        // An encrypted PEM cannot be used without its passphrase either.
        await page.Locator("#enc-key").FillAsync(encryptedPem);
        await Assertions.Expect(error).ToContainTextAsync("needs the private key");

        // Plain garbage stays on the same friendly path.
        await page.Locator("#enc-key").FillAsync("this is not a pem");
        await Assertions.Expect(error).ToContainTextAsync("needs the private key");

        // And the app recovers immediately: a valid PEM right after still signs.
        await page.Locator("#enc-key").FillAsync(privatePem);
        await Assertions.Expect(page.Locator("#encoded-token")).ToBeVisibleAsync();

        Assert.True(consoleErrors.Count == 0,
            $"Expected no console errors, but got:\n{string.Join("\n", consoleErrors)}");
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

    [Fact]
    public async Task The_app_drives_its_main_flows_without_any_console_errors()
    {
        // Collectors attach before the app renders so boot-time failures are caught too:
        // a renderer crash used to surface only as generic per-test timeouts (#28).
        var page = await fixture.OpenPageAsync();
        var consoleErrors = CollectConsoleErrors(page);
        await page.WaitForSelectorAsync(".app-title");

        // Drive every main flow once: decode, verify, encode, tab switch.
        await page.Locator("#token-box").FillAsync(CanonicalToken);
        await page.Locator("#key-box").FillAsync(CanonicalSecret);
        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();
        await page.Locator("#enc-header").FillAsync("""{"alg":"HS256","typ":"JWT"}""");
        await page.Locator("#enc-payload").FillAsync("""{"sub":"smoke"}""");
        await page.Locator("#enc-key").FillAsync(CanonicalSecret);
        await page.GetByRole(AriaRole.Tab, new() { Name = "Decode" }).ClickAsync();

        // Fail with the actual browser-side exception, not a timeout.
        Assert.True(consoleErrors.Count == 0,
            $"Expected no console errors, but got:\n{string.Join("\n", consoleErrors)}");
    }

    /// <summary>Strips whitespace so a pretty-printed editor value compares equal to compact JSON.</summary>
    private static string Compact(string json) =>
        Regex.Replace(json, @"\s+", "");

    /// <summary>Attaches console and uncaught-error collectors; the returned list must stay empty.</summary>
    private static List<string> CollectConsoleErrors(IPage page)
    {
        var errors = new List<string>();
        page.Console += (_, msg) =>
        {
            if (msg.Type == "error")
                errors.Add(msg.Text);
        };
        page.PageError += (_, exception) => errors.Add($"uncaught: {exception}");
        return errors;
    }

    /// <summary>A fresh RSA key pair in the two PEM shapes the app advertises.</summary>
    private static (string PrivatePkcs8Pem, string PublicSpkiPem) MakeRs256KeyPair()
    {
        using var rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '='));
    }

    /// <summary>
    /// Builds an RS256 token with BCL crypto only — independent of the app under test —
    /// plus the matching public PEM and a foreign one for the negative case.
    /// </summary>
    private static (string Token, string MatchingPublicPem, string ForeignPublicPem) MakeRs256TokenPair()
    {
        using var signer = RSA.Create(2048);
        using var foreign = RSA.Create(2048);

        var header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"RS256","typ":"JWT"}"""));
        var payload = Base64Url(Encoding.UTF8.GetBytes("""{"sub":"e2e-rs256"}"""));
        var signingInput = $"{header}.{payload}";
        var signature = signer.SignData(
            Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return (
            $"{signingInput}.{Base64Url(signature)}",
            signer.ExportSubjectPublicKeyInfoPem(),
            foreign.ExportSubjectPublicKeyInfoPem());
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
