/// email.rs — Send transactional email via local Postfix (SMTP port 25)

use anyhow::Result;
use lettre::{
    message::header::ContentType,
    transport::smtp::SmtpTransport,
    Address, Message, Transport,
};

pub fn send_verification(to_email: &str, username: &str, token: &str, base_url: &str) -> Result<()> {
    let body = format!(
        "Hello {username},\n\n\
        Someone registered a CryptIRC account with this email address.\n\
        Click the link below to verify your email and activate your account:\n\n\
        {base_url}/auth/verify?token={token}\n\n\
        This link expires in 24 hours.\n\n\
        If you did not register, ignore this email.\n\n\
        — CryptIRC"
    );

    let from_addr: Address = "noreply@cryptirc.local".parse()?;
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
