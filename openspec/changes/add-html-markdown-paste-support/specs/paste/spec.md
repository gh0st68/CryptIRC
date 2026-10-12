## Purpose

CryptIRC Paste lets users share text snippets by unguessable link with optional password and expiry. This capability adds an explicit render type so Markdown pastes read as formatted documents and single-file HTML/JS pastes run as a sandboxed page, and so the chat input can create the right kind of paste from pasted content.

## ADDED Requirements

### Requirement: Paste content types
Every paste SHALL carry a render type of `text`, `markdown`, or `html`. A creation request that omits the type SHALL create a `text` paste; a request with an unrecognized type SHALL be rejected with a client error. A stored paste that predates the type field (no stored type) SHALL be treated as `text`. The existing behavior for size limit (500 KB), expiry, password hashing, language metadata, author attribution, and per-user/per-IP rate limits SHALL apply unchanged to all types.

#### Scenario: Omitted type defaults to text
- **WHEN** a paste is created without a type
- **THEN** the created paste is stored and rendered as `text`

#### Scenario: Legacy paste stays text
- **WHEN** a paste stored before this change (no type field) is viewed
- **THEN** it renders exactly as before, as an escaped text view

#### Scenario: Unknown type rejected
- **WHEN** a creation request specifies a type other than `text`, `markdown`, or `html`
- **THEN** the request is rejected and no paste is stored

#### Scenario: Size limit applies to all types
- **WHEN** an `html` or `markdown` paste exceeds 500 KB
- **THEN** creation is rejected with the same limit error as before

### Requirement: Markdown paste rendering
Viewing a `markdown` paste SHALL render it as formatted HTML styled with the CryptIRC theme, supporting at least headings, paragraphs, emphasis, links, ordered and unordered lists, blockquotes, tables, task lists, and fenced code blocks. Raw HTML embedded in the Markdown source MUST NOT execute and MUST NOT be able to alter the CryptIRC page; such markup is escaped or removed. Rendering SHALL be identical for public pastes and for password-protected pastes after a successful unlock.

#### Scenario: Markdown structure renders
- **WHEN** a `markdown` paste containing a heading, a list, a table, and a fenced code block is viewed
- **THEN** the page shows formatted HTML elements rather than literal Markdown markers, and the code block content is preserved

#### Scenario: Embedded raw HTML does not execute
- **WHEN** a `markdown` paste contains a script tag or an event-handler attribute
- **THEN** no script runs, and the unsafe markup is not present as active HTML in the rendered page

#### Scenario: Unlocked markdown renders formatted
- **WHEN** the correct password for a protected `markdown` paste is submitted
- **THEN** the rendered result is the same formatted view as for a public markdown paste

### Requirement: HTML app paste rendering
Viewing an `html` paste SHALL present the document as a running page: its scripts execute, it owns a page-sized viewport, and a toolbar provides an App/Source toggle and an affordance to open the app on its own. The running app MUST be isolated from the CryptIRC application: it MUST NOT read CryptIRC cookies, session credentials, localStorage or sessionStorage, and MUST NOT access or navigate the parent document or top-level page. The app MAY load external resources, including CDN scripts and styles, API requests, and remote images or media. The Source view SHALL show the escaped source, and a raw link SHALL remain available.

#### Scenario: App runs with scripts
- **WHEN** an `html` paste whose document runs JavaScript (including one that loads a script from a CDN) is viewed
- **THEN** the app executes and renders inside the paste page

#### Scenario: App cannot reach CryptIRC origin state
- **WHEN** a rendered app attempts to read `document.cookie`, `localStorage`, or the parent document
- **THEN** the access fails or returns empty because the app has an opaque origin, and no CryptIRC session token is reachable

#### Scenario: App cannot take over the page
- **WHEN** a rendered app attempts to navigate the top-level window to another URL
- **THEN** the navigation is blocked and the paste page remains

#### Scenario: App and Source toggle
- **WHEN** the user switches the toolbar to Source and back to App
- **THEN** the escaped source is shown, then the app is shown again

#### Scenario: Only HTML pastes render as apps
- **WHEN** the app view is requested for a `text` or `markdown` paste
- **THEN** no app is rendered (not-found or equivalent refusal)

### Requirement: Text paste rendering stays source-only
`text` pastes SHALL keep the current rendering: escaped source in a preformatted block with the language label, creation time, author, expiry, and raw link. No HTML or JavaScript from a `text` paste SHALL execute, even when the source looks like a complete HTML document.

#### Scenario: HTML-looking text paste stays escaped
- **WHEN** a `text` paste contains a complete HTML document with a script tag
- **THEN** the page shows the escaped source and no script executes

### Requirement: Raw endpoint remains source-faithful
For every paste type the raw endpoint SHALL return the stored source bytes unchanged with a `text/plain; charset=utf-8` content type, so that no paste is ever executed at the raw URL with CryptIRC origin privileges. Password verification, expiry, and rate limiting for raw requests SHALL remain unchanged. The paste view's GET SHALL keep ignoring any password supplied in the URL query and SHALL unlock only through the POST form.

#### Scenario: Raw HTML paste returns source
- **WHEN** the raw endpoint of an `html` paste is requested
- **THEN** the response is the exact source text with a plain-text content type and nothing executes

#### Scenario: View GET still requires the unlock form
- **WHEN** a protected paste's view URL is requested with a password query parameter
- **THEN** the unlock form is shown and the content is not revealed

### Requirement: Password-protected pastes keep parity
The unlock flow SHALL be unchanged: a protected paste's view shows the unlock form without revealing the paste type or content, a correct password renders the same type-aware view as a public paste, and repeated failures stay rate-limited. A protected `html` paste SHALL render through the same sandboxed app machinery as a public one after unlock.

#### Scenario: Unlocked HTML app runs
- **WHEN** the correct password for a protected `html` paste is submitted
- **THEN** the paste page runs the app in the sandbox

#### Scenario: Wrong password reveals nothing
- **WHEN** an incorrect password is submitted
- **THEN** the unlock form is shown again and no paste content or type is revealed

### Requirement: Smart paste offers type-aware paste creation
When content is pasted into the chat input box, the client SHALL classify it and, when it is at least five lines or recognizable as a complete HTML document, show a smart-paste dialog with a type-appropriate primary action: create an `html` paste for a complete HTML document, create a `markdown` paste for multiline content with Markdown structure (headings, fenced code, lists, blockquotes, tables, or links), otherwise create a `text` paste as today. The dialog SHALL always offer "Paste as text", which inserts the raw content into the input without creating a paste. Creating a paste SHALL insert the paste URL into the chat input, and a failed creation SHALL leave the original content available in the input. The manual Paste modal's HTML and Markdown choices SHALL create the corresponding types and indicate that they render as a page or formatted document.

#### Scenario: HTML paste offers app paste
- **WHEN** a complete HTML document is pasted into the chat input
- **THEN** the dialog offers creating an HTML app paste, and choosing it creates an `html` paste and puts its URL in the input

#### Scenario: Markdown paste offers markdown paste
- **WHEN** multiline Markdown with a heading and a list is pasted into the chat input
- **THEN** the dialog offers creating a markdown paste, and choosing it creates a `markdown` paste and puts its URL in the input

#### Scenario: Plain text keeps existing flow
- **WHEN** five or more lines of ordinary text are pasted
- **THEN** the dialog offers the existing text paste action

#### Scenario: Paste as text creates nothing
- **WHEN** the user chooses "Paste as text"
- **THEN** no paste is created and the raw content is placed in the input

#### Scenario: Short ordinary chat is not interrupted
- **WHEN** one or two lines of ordinary non-HTML text are pasted
- **THEN** no smart-paste dialog appears

#### Scenario: Manual modal creates typed paste
- **WHEN** the user creates a paste from the Paste modal with HTML or Markdown selected
- **THEN** the paste is stored with the matching type and renders accordingly

### Requirement: Sandbox framing policy is narrowly scoped
The rendered app document SHALL be embeddable only by the same-origin CryptIRC paste page, and SHALL NOT receive same-origin privileges. Every other CryptIRC response SHALL keep `X-Frame-Options: DENY` and `frame-ancestors 'none'`. The paste page's policy SHALL allow same-origin framing in addition to its existing allowances, and the app route exception MUST be limited to that route.

#### Scenario: Cross-origin framing stays blocked
- **WHEN** any CryptIRC page other than the paste-page's own app embed attempts to frame the app document, or any origin attempts to frame another CryptIRC page
- **THEN** the frame is blocked by the framing policy

#### Scenario: App route exception is scoped
- **WHEN** a non-app CryptIRC route is requested
- **THEN** its response still carries `X-Frame-Options: DENY` and `frame-ancestors 'none'`
