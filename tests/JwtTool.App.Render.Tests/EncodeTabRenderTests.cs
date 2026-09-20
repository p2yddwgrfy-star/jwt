using JwtTool.App.Pages;
using JwtTool.TokenOperations;

namespace JwtTool.App.Render.Tests;

/// <summary>
/// EncodeTab's presenter rules, in-process: a complete draft renders the signed Token,
/// a malformed editor renders the friendly error (and suppresses the key hint while it
/// shows), and edits flow back to the owner as one draft — never held locally.
/// </summary>
public class EncodeTabRenderTests : BunitContext
{
    [Fact]
    public void A_complete_draft_renders_the_signed_token()
    {
        var cut = RenderTab(key: "k");

        Assert.NotNull(cut.Find("#encoded-token"));
        Assert.Empty(cut.FindAll(".parse-error"));
    }

    [Fact]
    public void A_malformed_editor_renders_the_friendly_error_and_suppresses_the_hint()
    {
        // The friendly error needs a key present: an empty key short-circuits the flow
        // to "nothing to sign yet" before the header/payload is ever parsed.
        var cut = RenderTab(payload: "not json", key: "k");

        Assert.NotNull(cut.Find(".parse-error"));
        Assert.Empty(cut.FindAll("p.hint"));
    }

    [Fact]
    public void An_edit_flows_back_to_the_owner_as_one_draft()
    {
        EncodeDraft? emitted = null;
        var cut = RenderTab(onDraftChanged: d => emitted = d);

        cut.Find("#enc-key").Input("the key");

        Assert.NotNull(emitted);
        Assert.Equal("the key", emitted.Key);
        Assert.Equal(Header(), emitted.HeaderJson);
        Assert.Equal(SignatureAlgorithm.HS256, emitted.Algorithm);
    }

    // Instance method: Render<T> is BunitContext's instance API.
    private IRenderedComponent<EncodeTab> RenderTab(
        string key = "",
        string payload = """{"sub":"1"}""",
        Action<EncodeDraft>? onDraftChanged = null) => Render<EncodeTab>(parameters => parameters
            .Add(p => p.Draft, new EncodeDraft(Header(), payload, key, SignatureAlgorithm.HS256))
            .Add(p => p.DraftChanged, d => (onDraftChanged ?? (_ => { }))(d)));

    private static string Header() => """{"alg":"HS256","typ":"JWT"}""";
}
