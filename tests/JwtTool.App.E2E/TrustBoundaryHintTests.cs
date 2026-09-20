using Microsoft.Playwright;
using Xunit;

namespace JwtTool.App.E2E;

/// <summary>
/// The privacy hints must state the browser trust boundary explicitly (#32): keys are
/// used without network egress, but page-scoped script can read in-memory key material.
/// </summary>
[Collection("App")]
public sealed class TrustBoundaryHintTests(AppFixture fixture)
{
    // Both boundary statements, as they literally render in the hint copy.
    private const string NoEgress = "without sending it anywhere";
    private const string PageScript = "browser extensions";

    [Fact]
    public async Task The_rs256_encode_hint_states_the_browser_trust_boundary()
    {
        var page = await fixture.OpenPageAsync();
        await page.WaitForSelectorAsync(".app-title");

        await page.GetByRole(AriaRole.Tab, new() { Name = "Encode" }).ClickAsync();
        await page.Locator(".encode-controls select").SelectOptionAsync("RS256");

        // The RS256 key hint says both halves: no network egress, and page script
        // (such as browser extensions) can read the in-memory key.
        await Assertions.Expect(page.Locator($"text={NoEgress}")).ToBeVisibleAsync();
        await Assertions.Expect(page.Locator($"text={PageScript}")).ToBeVisibleAsync();
        // And it is the RS256 variant, naming the private key.
        await Assertions.Expect(page.Locator("text=Pick a private key to sign the Token")).ToBeVisibleAsync();
    }

    [Fact]
    public async Task The_verify_hint_states_the_browser_trust_boundary()
    {
        var page = await fixture.OpenPageAsync();
        await page.WaitForSelectorAsync(".app-title");

        // The hint renders only while the key box is empty — filling the key swaps it
        // for the verdict — so assert the boundary copy before pasting a key.
        await page.Locator("#token-box").FillAsync(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.OIdBcuDlUXH5RFWwkD9lnJXaiInC7akyvNRDBChUZc");

        await Assertions.Expect(page.Locator($"text={NoEgress}")).ToBeVisibleAsync();
        await Assertions.Expect(page.Locator($"text={PageScript}")).ToBeVisibleAsync();
    }
}
