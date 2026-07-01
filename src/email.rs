/// email.rs — Send transactional email via local Postfix (SMTP port 25)
///
/// ## Transport security (audit #66)
///
/// We deliberately hand mail to the *local* Postfix instance on `127.0.0.1:25` over a
/// plaintext, unauthenticated SMTP session (`builder_dangerous`). This is safe ONLY
/// because the hop is loopback (never traverses a network): there is no on-wire exposure
/// and no credentials to leak on this leg.
///
/// The onward, internet-facing security is Postfix's responsibility and MUST be
/// configured there:
///   - opportunistic/forced STARTTLS on outbound delivery,
///   - DANE (TLSA) and/or MTA-STS so downstream MX TLS can't be silently stripped.
///
/// Because the verify/reset links in these messages are bearer tokens, their lifetimes
/// MUST stay short (verify 24h, reset 1h — see auth.rs) to bound the window in which a
/// leaked message is useful. Do NOT raise those lifetimes without revisiting this note.

use anyhow::{bail, Result};
use lettre::{
    message::header::ContentType,
    transport::smtp::SmtpTransport,
    Address, Message, Transport,
};

/// Validate a single email address destined for an SMTP envelope/header (audit #67).
///
/// auth.rs (register/reset) should call this BEFORE constructing a message so that
/// header-injection and multi-recipient payloads are rejected early. We reject:
///   - empty / over-long input,
///   - any control character (notably CR/LF) — these enable SMTP/header injection,
///   - whitespace and commas/semicolons — i.e. anything that could smuggle a second
///     address or header,
///   - addresses lettre itself can't parse as a single RFC 5321 mailbox.
///
/// Returns `true` only for a single, well-formed address. Note this is a syntactic guard;
/// it does not prove the mailbox is deliverable.
pub fn validate_email(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty() || addr.len() > 254 {
        return false;
    }
    // Reject control chars (CR/LF/NUL/etc.) and any whitespace or separator that could
    // introduce a second address or a forged header line.
    if addr.chars().any(|c| {
        c.is_control() || c.is_whitespace() || c == ',' || c == ';'
    }) {
        return false;
    }
    // Final authority: must parse as exactly one address via the typed parser.
    addr.parse::<Address>().is_ok()
}

/// Send the account-verification email.
///
/// Returns `Err` on any failure — including `from_email`/`to_email` parse errors and
/// SMTP send failures — so callers can surface the problem to the user rather than
/// failing silently (audit #134). Callers should treat an `Err` here as "the message was
/// NOT sent".
///
/// Future improvement: persist a send job and retry/queue on transient SMTP failure
/// instead of relying on a single synchronous attempt.
pub fn send_verification(to_email: &str, username: &str, token: &str, base_url: &str, from_email: &str) -> Result<()> {
    if !validate_email(from_email) { bail!("Invalid from address"); }
    if !validate_email(to_email) { bail!("Invalid recipient address"); }
    let body = format!(
        "Hello {username},\n\n\
        Someone registered a CryptIRC account with this email address.\n\
        Click the link below to verify your email and activate your account:\n\n\
        {base_url}/auth/verify?token={token}\n\n\
        This link expires in 24 hours.\n\n\
        If you did not register, ignore this email.\n\n\
        — CryptIRC"
    );

    let from_addr: Address = from_email.parse()?;
    let to_addr: Address = to_email.parse()?;

    let email = Message::builder()
        .from(lettre::message::Mailbox::new(Some("CryptIRC".into()), from_addr))
        .to(lettre::message::Mailbox::new(None, to_addr))
        .subject("Verify your CryptIRC account")
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;

    // Connect to local Postfix on port 25 — no auth, no TLS
    let mailer = SmtpTransport::builder_dangerous("127.0.0.1")
        .port(25)
        .build();

    mailer.send(&email)?;
    Ok(())
}

/// Send the password-reset email.
///
/// Returns `Err` on any failure — including `from_email`/`to_email` parse errors and
/// SMTP send failures — so callers can surface the problem rather than failing silently
/// (audit #134). An `Err` means the message was NOT sent.
///
/// Future improvement: persist a send job and retry/queue on transient SMTP failure
/// instead of relying on a single synchronous attempt.
pub fn send_password_reset(to_email: &str, username: &str, token: &str, base_url: &str, from_email: &str) -> Result<()> {
    if !validate_email(from_email) { bail!("Invalid from address"); }
    if !validate_email(to_email) { bail!("Invalid recipient address"); }
    let body = format!(
        "Hello {username},\n\n\
        Someone requested a password reset for your CryptIRC account.\n\
        Click the link below to set a new password:\n\n\
        {base_url}/auth/reset?token={token}\n\n\
        This link expires in 1 hour.\n\n\
        If you did not request this, ignore this email — your password will not be changed.\n\n\
        — CryptIRC"
    );

    let from_addr: Address = from_email.parse()?;
    let to_addr: Address = to_email.parse()?;

    let email = Message::builder()
        .from(lettre::message::Mailbox::new(Some("CryptIRC".into()), from_addr))
        .to(lettre::message::Mailbox::new(None, to_addr))
        .subject("Reset your CryptIRC password")
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;

    let mailer = SmtpTransport::builder_dangerous("127.0.0.1")
        .port(25)
        .build();

    mailer.send(&email)?;
    Ok(())
}
