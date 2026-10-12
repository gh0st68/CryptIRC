/// paste_render.rs — safe server-side Markdown rendering for pastes.
///
/// Markdown is untrusted user input that is rendered on the CryptIRC origin, so
/// the pipeline is deliberately two-stage: pulldown-cmark parses GFM into HTML,
/// then ammonia sanitizes it. Raw HTML embedded in the source is reduced to
/// ammonia's safe allowlist — scripts, event-handler attributes, and non
/// http(s)/mailto URLs can never reach the paste page. See the change design D2
/// and the paste view in main.rs (`render_paste`).

use pulldown_cmark::{html, Options, Parser};

/// Render pasted Markdown to sanitized HTML.
pub fn render_markdown(src: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_GFM);

    let parser = Parser::new_ext(src, options);
    let mut rendered = String::with_capacity(src.len() + src.len() / 2);
    html::push_html(&mut rendered, parser);

    let mut sanitizer = ammonia::Builder::default();
    sanitizer.link_rel(Some("noopener noreferrer"));
    // Ammonia's default allowlist drops `<input>`, which is how pulldown-cmark
    // renders task-list checkboxes (disabled and inert; forms are stripped, so an
    // input can never submit anywhere). Allow just the checkbox shape so task
    // lists read correctly on the paste page.
    sanitizer.add_tags(["input"]);
    sanitizer.add_tag_attributes("input", ["type", "checked", "disabled"]);

    sanitizer.clean(&rendered).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_task_list_input(out: &str) {
        // Task-list items render as disabled checkbox inputs plus the item text.
        assert!(out.contains("type=\"checkbox\""), "{}", out);
        assert!(out.contains("disabled"), "{}", out);
        assert!(out.contains("done"), "{}", out);
    }

    #[test]
    fn renders_common_markdown_structure() {
        let src = "# Title\n\n- one\n- two\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n```rust\nfn main() {}\n```\n\n> quote\n\n- [x] done\n";
        let out = render_markdown(src);
        assert!(out.contains("<h1>Title</h1>"), "{}", out);
        assert!(out.contains("<ul>"), "{}", out);
        assert!(out.contains("<table>"), "{}", out);
        assert!(out.contains("<blockquote>"), "{}", out);
        assert!(out.contains("<pre><code"), "{}", out);
        assert!(out.contains("fn main() {}"), "{}", out);
        assert_task_list_input(&out);
    }

    #[test]
    fn strips_scripts_and_event_handlers() {
        let out = render_markdown(
            "<script>alert(1)</script>\n\n<img src=\"x\" onerror=\"alert(2)\">\n\n<p onclick=\"alert(3)\">click</p>\n",
        );
        assert!(!out.contains("<script"), "{}", out);
        assert!(!out.to_ascii_lowercase().contains("alert(1)"), "{}", out);
        assert!(!out.to_ascii_lowercase().contains("onerror"), "{}", out);
        assert!(!out.to_ascii_lowercase().contains("onclick"), "{}", out);
        // Ordinary content from an otherwise stripped wrapper remains readable.
        assert!(out.contains("click"), "{}", out);
    }

    #[test]
    fn strips_dangerous_url_schemes() {
        let out = render_markdown("[click](javascript:alert(1))\n\n[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)\n");
        let lower = out.to_ascii_lowercase();
        assert!(!lower.contains("javascript:"), "{}", out);
        assert!(!lower.contains("data:text/html"), "{}", out);
    }

    #[test]
    fn safe_links_get_noopener_rel() {
        let out = render_markdown("[example](https://example.com/docs)");
        assert!(out.contains("href=\"https://example.com/docs\""), "{}", out);
        assert!(out.contains("rel=\"noopener noreferrer\""), "{}", out);
    }

    #[test]
    fn empty_and_plain_text_render() {
        assert!(render_markdown("").is_empty());
        assert!(render_markdown("just text").contains("just text"));
    }
}
