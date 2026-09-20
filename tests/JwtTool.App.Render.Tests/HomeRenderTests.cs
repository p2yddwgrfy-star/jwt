using JwtTool.App.Pages;

namespace JwtTool.App.Render.Tests;

/// <summary>
/// Home's page-state rules, in-process: the Clear reset must not leave stale derived
/// state, the Encode draft survives tab switches (#9), and the Tweak &amp; re-encode
/// handoff loads the decoded JSON into the Encode editors. Interactions go through DOM
/// events only — the same way the browser E2E suite drives the page, one adapter faster.
/// </summary>
public class HomeRenderTests : BunitContext
{
    // Canonical jwt.io token signed with "your-256-bit-secret".
    private const string CanonicalToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    [Fact]
    public void Clear_empties_the_token_drops_the_verdict_and_brings_the_hints_back()
    {
        var cut = Render<Home>();

        cut.Find("#token-box").Input(CanonicalToken);
        Assert.NotNull(cut.Find(".two-pane")); // decoded panes render

        cut.Find("#clear-input").Click();

        Assert.Equal("", cut.Find("#token-box").GetAttribute("value"));
        Assert.Empty(cut.FindAll(".two-pane"));
        Assert.Empty(cut.FindAll(".verdict"));
        Assert.Contains("Decode needs no key", cut.Find("p.hint").TextContent);
    }

    [Fact]
    public void After_clear_a_new_token_mounts_the_verify_section_fresh()
    {
        var cut = Render<Home>();

        cut.Find("#token-box").Input(CanonicalToken);
        cut.Find("#key-box").Input("your-256-bit-secret");
        Assert.NotNull(cut.Find(".verdict.valid"));

        cut.Find("#clear-input").Click();
        Assert.Empty(cut.FindAll(".verdict")); // the section unmounts with the decoded state

        // A new token mounts the verify section again — the hint, never a stale verdict.
        cut.Find("#token-box").Input(CanonicalToken);
        Assert.Contains("Paste a Key to verify the Signature.", cut.Find(".verify-section p.hint").TextContent);
        Assert.Empty(cut.FindAll(".verdict"));
    }

    [Fact]
    public void The_encode_draft_survives_decode_encode_tab_switches()
    {
        var cut = Render<Home>();
        SwitchTo(cut, "Encode");

        cut.Find("#enc-header").Input("""{"alg":"HS256","typ":"JWT","x":"kept"}""");
        SwitchTo(cut, "Decode");
        SwitchTo(cut, "Encode");

        Assert.Contains("\"x\":\"kept\"", cut.Find("#enc-header").GetAttribute("value")!.Replace(" ", ""));
    }

    [Fact]
    public void Tweak_and_re_encode_loads_the_decoded_json_into_the_encode_editors()
    {
        var cut = Render<Home>();
        cut.Find("#token-box").Input(CanonicalToken);

        cut.FindAll(".pane-head button").Single(b => b.TextContent.Contains("Tweak")).Click();

        Assert.Contains("\"alg\":\"HS256\"", cut.Find("#enc-header").GetAttribute("value")!.Replace(" ", ""));
        Assert.Contains("John Doe", cut.Find("#enc-payload").GetAttribute("value"));
    }

    private static void SwitchTo(IRenderedComponent<Home> cut, string tab) =>
        cut.FindAll("nav.tabs button").Single(b => b.TextContent.Trim() == tab).Click();
}
