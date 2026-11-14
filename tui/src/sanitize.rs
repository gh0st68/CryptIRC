//! Terminal-safe text.
//!
//! Everything a remote party controls — message text, nicks, topics, channel
//! and network labels, bot answers, server error strings — ends up in a ratatui
//! `Span`, and ratatui writes a cell's characters to the terminal unchanged. It
//! only skips characters it measures as zero-width, and `unicode-width` does NOT
//! measure ESC, CR, BS or the C1 range as zero. So without this an IRC peer
//! could send `ESC ] 0 ; …` (set the window title), `ESC ] 52 ; …` (write the
//! clipboard), cursor/screen moves, `ESC [ 6 n` (make the terminal type a reply
//! into our input) and so on, straight to the user's terminal.
//!
//! `clean` is applied by the renderer to every server-derived string before it
//! becomes a `Span`, and to pasted/tab-completed text before it enters the input
//! line. It:
//!
//! * strips mIRC formatting codes (bold, colour, italic, underline, reverse,
//!   strikethrough, monospace, reset) INCLUDING a colour code's digits, so
//!   `\x0304red` shows as `red` — the TUI does not render IRC colours;
//! * turns TAB / LF and the Unicode line/paragraph separators into a space (they
//!   would otherwise move the cursor and tear the layout);
//! * drops every other control character: all of C0, DEL, and C1 (U+0080..U+009F
//!   — U+009B is a one-character CSI on many terminals);
//! * drops the bidi embedding/override/isolate controls and the directional
//!   marks, which can make a line display as something other than what it says.
//!
//! The common case (nothing to remove) borrows and allocates nothing.

use std::borrow::Cow;

/// True for any character `clean` would change.
fn needs_work(c: char) -> bool {
    c.is_control() || is_bidi_control(c) || c == '\u{2028}' || c == '\u{2029}'
}

/// Bidirectional formatting characters: ALM, LRM, RLM, the embeddings and
/// overrides (LRE RLE PDF LRO RLO) and the isolates (LRI RLI FSI PDI).
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Make `s` safe to hand to the terminal. See the module docs.
pub fn clean(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_work) {
        return Cow::Borrowed(s);
    }
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let digits = |from: usize, max: usize, pred: fn(&char) -> bool| -> usize {
        cs[from..].iter().take(max).take_while(|c| pred(c)).count()
    };
    while i < cs.len() {
        let c = cs[i];
        i += 1;
        match c {
            // mIRC colour: \x03[fg[,bg]], fg and bg are 1-2 decimal digits. A comma
            // only belongs to the code when a colour digit follows it.
            '\x03' => {
                let fg = digits(i, 2, char::is_ascii_digit);
                if fg > 0 {
                    i += fg;
                    if i + 1 < cs.len() && cs[i] == ',' && cs[i + 1].is_ascii_digit() {
                        i += 1;
                        i += digits(i, 2, char::is_ascii_digit);
                    }
                }
            }
            // Hex colour: \x04[RRGGBB[,RRGGBB]].
            '\x04' => {
                if digits(i, 6, char::is_ascii_hexdigit) == 6 {
                    i += 6;
                    if i < cs.len() && cs[i] == ',' && digits(i + 1, 6, char::is_ascii_hexdigit) == 6 {
                        i += 7;
                    }
                }
            }
            // Bold, reset, monospace, reverse, italic, strikethrough, underline:
            // single-byte toggles with no parameters.
            '\x02' | '\x0f' | '\x11' | '\x16' | '\x1d' | '\x1e' | '\x1f' => {}
            '\t' | '\n' | '\u{2028}' | '\u{2029}' => out.push(' '),
            c if c.is_control() || is_bidi_control(c) => {}
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::clean;

    fn safe(s: &str) -> bool {
        !s.chars().any(|c| c.is_control()
            || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    }

    #[test]
    fn plain_text_is_borrowed_untouched() {
        for s in ["", "hello", "héllo wörld 😀 日本語", "a,b 12 #chan @op", "e\u{301}"] {
            assert!(matches!(clean(s), std::borrow::Cow::Borrowed(_)), "{s:?}");
            assert_eq!(clean(s), s);
        }
    }

    #[test]
    fn terminal_escapes_are_removed() {
        let cases = [
            "osc0 \x1b]0;PWNTITLE\x07 end",
            "osc52 \x1b]52;c;UFdOQ0xJUA==\x07 end",
            "csi \x1b[38;5;196mREDMARK\x1b[0m end",
            "c1csi \u{009b}31mC1MARK end",
            "osc8 \x1b]8;;http://evil.example/\x07LINKTEXT\x1b]8;;\x07 end",
            "dsr \x1b[6n end",
            "cr \rCRMARK end",
            "bs ABC\x08\x08\x08XYZ end",
            "del \x7f end",
            "nul \0 end",
            "st \x1b\\ \u{009c} \u{0090}dcs\u{009c}",
        ];
        for s in cases {
            let c = clean(s);
            assert!(safe(&c), "{s:?} -> {c:?}");
            assert!(!c.contains('\x1b'));
        }
        // The text around an escape survives; the escape's introducer does not.
        assert_eq!(clean("a\x1b[6nb"), "a[6nb");
        assert_eq!(clean("cr \rCRMARK"), "cr CRMARK");
    }

    #[test]
    fn bidi_controls_are_removed() {
        assert_eq!(clean("bidi \u{202E}GNIRTS\u{202C} end"), "bidi GNIRTS end");
        assert_eq!(clean("\u{2066}x\u{2069}\u{200F}\u{200E}\u{061C}"), "x");
    }

    #[test]
    fn mirc_formatting_is_stripped_with_its_digits() {
        assert_eq!(clean("\x0304red"), "red");
        assert_eq!(clean("\x034,12on blue\x03 plain"), "on blue plain");
        assert_eq!(clean("\x0312,5x"), "x");
        assert_eq!(clean("\x03,5x"), ",5x");            // no fg: \x03 is a bare reset
        assert_eq!(clean("\x0304,x"), ",x");            // comma not followed by a digit is text
        assert_eq!(clean("\x03123"), "3");              // at most two fg digits
        assert_eq!(clean("\x02bold\x02 \x1ditalic\x1d \x1funder\x1f \x16rev\x16 \x1estrike\x1e \x11mono\x11 \x0freset"),
                   "bold italic under rev strike mono reset");
        assert_eq!(clean("\x04FF0000red"), "red");
        assert_eq!(clean("\x04FF0000,00FF00x"), "x");
        assert_eq!(clean("\x04xyz"), "xyz");
        assert_eq!(clean("trailing\x03"), "trailing");
        assert_eq!(clean("trailing\x0304,"), "trailing,");
    }

    #[test]
    fn whitespace_controls_become_spaces() {
        assert_eq!(clean("a\tb\nc\u{2028}d\u{2029}e"), "a b c d e");
    }

    #[test]
    fn never_panics_and_always_safe_on_arbitrary_input() {
        // Every char in the C0/C1 ranges, every formatting byte at the end of
        // the string, mixed with multi-byte text.
        let mut s = String::new();
        for c in (0u32..0x200).filter_map(char::from_u32) { s.push(c); s.push('é'); }
        for cut in 0..s.chars().count() {
            let t: String = s.chars().take(cut).collect();
            assert!(safe(&clean(&t)));
        }
    }
}
