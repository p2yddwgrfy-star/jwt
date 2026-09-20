using JwtTool.App;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.App.Render.Tests;

/// <summary>
/// KeyEntry's rendered state rules, in-process — the state band between the flow unit
/// tests and the browser E2E suite. The empty-key hint (carrying the #32 trust-boundary
/// sentence, written once in KeyEntry) shows and hides by rule, the RS256 picker swaps
/// the label wording, and key edits flow back to the owner. Interactions go through
/// parameters and DOM events only.
/// </summary>
public class KeyEntryRenderTests : BunitContext
{
    private const string TrustBoundary =
        "It is used without sending it anywhere, but code running in the page (such as browser extensions) can read it.";

    private IRenderedComponent<KeyEntry> RenderKeyEntry(
        SignatureAlgorithm algorithm = SignatureAlgorithm.HS256,
        string key = "",
        bool showHint = true,
        bool boundaryHint = true,
        Action<string>? onKeyChanged = null,
        Action<SignatureAlgorithm>? onAlgorithmChanged = null) => Render<KeyEntry>(parameters => parameters
            .Add(p => p.Algorithm, algorithm)
            .Add(p => p.KeyText, key)
            .Add(p => p.KeyTextChanged, k => (onKeyChanged ?? (_ => { }))(k))
            .Add(p => p.AlgorithmChanged, a => (onAlgorithmChanged ?? (_ => { }))(a))
            .Add(p => p.TextAreaId, "test-key-box")
            .Add(p => p.ControlsClass, "test-controls")
            .Add(p => p.RsaKeyWording, "PEM key pair (public or private key)")
            .Add(p => p.RsaKeyPlaceholder, "-----BEGIN PUBLIC KEY-----")
            .Add(p => p.HintLead, "Paste a Key to verify the Signature.")
            .Add(p => p.BoundaryHint, boundaryHint)
            .Add(p => p.ShowHint, showHint));

    [Fact]
    public void An_empty_key_shows_the_hint_with_the_trust_boundary_sentence()
    {
        var cut = RenderKeyEntry(SignatureAlgorithm.HS256, key: "");

        var hint = cut.Find("p.hint");
        Assert.Contains("Paste a Key to verify the Signature.", hint.TextContent);
        Assert.Contains(TrustBoundary, hint.TextContent);
    }

    [Fact]
    public void A_key_text_hides_the_hint()
    {
        var cut = RenderKeyEntry(SignatureAlgorithm.HS256, key: "a secret");

        Assert.Empty(cut.FindAll("p.hint"));
    }

    [Fact]
    public void A_key_arriving_later_hides_the_hint_without_a_parent_re_render()
    {
        var cut = RenderKeyEntry(SignatureAlgorithm.HS256, key: "");
        Assert.NotEmpty(cut.FindAll("p.hint"));

        // The key is the owner's state: it changes only through the parameter.
        cut.Render(parameters => parameters.Add(p => p.KeyText, "a secret"));

        Assert.Empty(cut.FindAll("p.hint"));
    }

    [Fact]
    public void ShowHint_false_hides_the_hint_even_with_an_empty_key()
    {
        var cut = RenderKeyEntry(SignatureAlgorithm.HS256, key: "", showHint: false);

        Assert.Empty(cut.FindAll("p.hint"));
    }

    [Fact]
    public void BoundaryHint_false_drops_the_trust_boundary_but_keeps_the_lead()
    {
        var cut = RenderKeyEntry(SignatureAlgorithm.HS256, key: "", boundaryHint: false);

        var hint = cut.Find("p.hint");
        Assert.Contains("Paste a Key to verify the Signature.", hint.TextContent);
        Assert.DoesNotContain(TrustBoundary, hint.TextContent);
    }

    [Fact]
    public void The_rs256_picker_swaps_the_label_wording_and_placeholder()
    {
        var cut = RenderKeyEntry(SignatureAlgorithm.HS256, key: "");
        Assert.Contains("the Secret as text", cut.Find(".key-label").TextContent);

        cut.Render(parameters => parameters.Add(p => p.Algorithm, SignatureAlgorithm.RS256));

        Assert.Contains("PEM key pair (public or private key)", cut.Find(".key-label").TextContent);
        Assert.Equal(
            "-----BEGIN PUBLIC KEY-----",
            cut.Find("#test-key-box").GetAttribute("placeholder"));
    }

    [Fact]
    public void Choosing_an_algorithm_emits_it_to_the_owner()
    {
        SignatureAlgorithm? chosen = null;
        var cut = RenderKeyEntry(onAlgorithmChanged: a => chosen = a);

        cut.Find("select").Change("RS256");

        Assert.Equal(SignatureAlgorithm.RS256, chosen);
    }

    [Fact]
    public void Typing_a_key_emits_it_to_the_owner()
    {
        string? typed = null;
        var cut = RenderKeyEntry(onKeyChanged: k => typed = k);

        cut.Find("#test-key-box").Input("abc");

        Assert.Equal("abc", typed);
    }
}
