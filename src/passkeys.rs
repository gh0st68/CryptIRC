use crate::{
    auth, auth_busy_response, bearer_token, client_ip, run_auth_kdf, AppState, AuthOkBody, Msg,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;
use webauthn_rs::prelude::*;

const MAX_PASSKEYS: usize = 10;
const MAX_PENDING: usize = 2048;
const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const LOGIN_FAILED: &str = "Unable to sign in with a passkey.";
const SESSION_EXPIRED: &str = "Sign in again to manage passkeys.";
const INVALID_CHALLENGE: &str = "This passkey request expired. Start again.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Passkeys {
    handle: Uuid,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    id: Uuid,
    name: String,
    credential: Passkey,
    counter: u32,
    added_at: i64,
}

struct PendingRegistration {
    username: String,
    token: String,
    epoch: u64,
    handle: Uuid,
    name: String,
    password_verified: (String, i64),
    registration: PasskeyRegistration,
}

struct PendingLogin {
    authentication: DiscoverableAuthentication,
}

enum Ceremony {
    Register(Box<PendingRegistration>),
    Login(Box<PendingLogin>),
}

pub(crate) struct Service {
    webauthn: Option<Webauthn>,
    pending: Mutex<HashMap<Uuid, (Instant, Ceremony)>>,
    account_scans: tokio::sync::Semaphore,
}

impl Service {
    pub(crate) fn new(base_url: &str) -> Self {
        let webauthn = secure_url(base_url).and_then(|origin| {
            let rp_id = origin.host_str()?;
            WebauthnBuilder::new(rp_id, &origin)
                .ok()?
                .rp_name("CryptIRC")
                .build()
                .ok()
        });
        Self {
            webauthn,
            pending: Mutex::new(HashMap::new()),
            account_scans: tokio::sync::Semaphore::new(4),
        }
    }

    fn start(&self, ceremony: Ceremony) -> Option<Uuid> {
        let mut pending = self.pending.lock().ok()?;
        let now = Instant::now();
        pending.retain(|_, (expires, _)| now < *expires);
        if pending.len() >= MAX_PENDING {
            return None;
        }
        let id = Uuid::new_v4();
        pending.insert(id, (now + CHALLENGE_TTL, ceremony));
        Some(id)
    }

    fn take(&self, id: Uuid) -> Option<Ceremony> {
        let (expires, pending) = self.pending.lock().ok()?.remove(&id)?;
        (Instant::now() < expires).then_some(pending)
    }
}

// Match the externally configured origin, including its port, independent of
// reverse-proxy headers. Loopback development uses the DNS name localhost.
pub(crate) fn secure_url(base_url: &str) -> Option<Url> {
    let url = Url::parse(base_url).ok()?;
    let host = url.host_str()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    (url.scheme() == "https" || (url.scheme() == "http" && host == "localhost")).then_some(url)
}

pub(crate) fn origin_allowed(base_url: &str, headers: &HeaderMap, required: bool) -> bool {
    let Some(origin) = secure_url(base_url) else {
        return false;
    };
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(provided) = origins.next() else {
        return !required;
    };
    origins.next().is_none()
        && provided
            .to_str()
            .is_ok_and(|s| s == origin.origin().ascii_serialization())
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/passkeys", get(list).delete(remove))
        .route("/auth/passkeys/register/start", post(register_start))
        .route("/auth/passkeys/register/finish", post(register_finish))
        .route("/auth/passkeys/login/start", post(login_start))
        .route("/auth/passkeys/login/finish", post(login_finish))
        .layer(DefaultBodyLimit::max(16_384))
        .layer(middleware::from_fn(no_store))
}

async fn no_store(req: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(Msg {
            message: message.into(),
        }),
    )
        .into_response()
}

fn get_webauthn<'a>(state: &'a AppState, headers: &HeaderMap) -> Result<&'a Webauthn, Response> {
    let Some(webauthn) = state.passkeys.webauthn.as_ref() else {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Passkeys require a configured HTTPS origin.",
        ));
    };
    if !origin_allowed(&state.base_url, headers, true) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Passkey request origin does not match this server.",
        ));
    }
    Ok(webauthn)
}

fn account(state: &AppState, headers: &HeaderMap) -> Result<(String, String), Response> {
    let token =
        bearer_token(headers).ok_or_else(|| error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))?;
    let username = state
        .auth
        .validate_session(&token)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))?;
    Ok((username, token))
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, Response> {
    let (username, _) = account(&state, &headers)?;
    let user = state
        .auth
        .get_user(&username)
        .await
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))?;
    let passkeys: Vec<_> = user
        .passkeys
        .iter()
        .flat_map(|keys| &keys.entries)
        .map(|entry| json!({"id": entry.id, "name": entry.name, "added_at": entry.added_at}))
        .collect();
    Ok(Json(
        json!({"available": state.passkeys.webauthn.is_some(), "passkeys": passkeys}),
    ))
}

#[derive(Deserialize)]
struct RegisterStart {
    name: String,
    password: String,
}

async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterStart>,
) -> Result<Json<Value>, Response> {
    let webauthn = get_webauthn(&state, &headers)?;
    let (username, token) = account(&state, &headers)?;
    let epoch = state.auth.account_epoch(&username);
    let name = body.name.trim();
    if name.is_empty()
        || name.chars().count() > 64
        || name.chars().any(char::is_control)
        || body.password.is_empty()
        || body.password.len() > 1024
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Enter a passkey name and your current password.",
        ));
    }
    let ip = client_ip(&headers);
    let auth = state.auth.clone();
    let login = username.clone();
    let password = body.password;
    let verified = run_auth_kdf(move || async move {
        auth.verify_current_password(&login, &password, ip.as_deref())
            .await
    })
    .await
    .ok_or_else(auth_busy_response)?
    .map_err(|_| {
        error(
            StatusCode::UNAUTHORIZED,
            "Unable to verify the current password.",
        )
    })?;
    let user = state
        .auth
        .get_user(&username)
        .await
        .filter(|u| u.verified && !u.disabled)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))?;
    let (handle, exclude) = match user.passkeys {
        Some(keys) if keys.entries.len() >= MAX_PASSKEYS => {
            return Err(error(
                StatusCode::CONFLICT,
                "Remove a passkey before adding another.",
            ));
        }
        Some(keys) => (
            keys.handle,
            Some(
                keys.entries
                    .iter()
                    .map(|e| e.credential.cred_id().clone())
                    .collect(),
            ),
        ),
        None => (Uuid::new_v4(), None),
    };
    let (options, registration) = webauthn
        .start_passkey_registration(handle, &username, &username, exclude)
        .map_err(|_| auth_busy_response())?;
    let mut options = serde_json::to_value(options).map_err(|_| auth_busy_response())?;
    // A discoverable passkey allows opening the authenticator picker before the
    // user identifies an account, so the login start endpoint discloses nothing.
    options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
    options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(true);
    let pending = PendingRegistration {
        username,
        token,
        epoch,
        handle,
        name: name.into(),
        password_verified: verified,
        registration,
    };
    let id = state
        .passkeys
        .start(Ceremony::Register(Box::new(pending)))
        .ok_or_else(auth_busy_response)?;
    Ok(Json(json!({"id": id, "options": options})))
}

#[derive(Deserialize)]
struct RegisterFinish {
    id: Uuid,
    credential: RegisterPublicKeyCredential,
}

async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinish>,
) -> Result<StatusCode, Response> {
    let webauthn = get_webauthn(&state, &headers)?;
    let (username, token) = account(&state, &headers)?;
    let Some(Ceremony::Register(pending)) = state.passkeys.take(body.id) else {
        return Err(error(StatusCode::BAD_REQUEST, INVALID_CHALLENGE));
    };
    if pending.username != username || pending.token != token {
        return Err(error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED));
    }
    let credential = webauthn
        .finish_passkey_registration(&body.credential, &pending.registration)
        .map_err(|_| {
            error(
                StatusCode::BAD_REQUEST,
                "The new passkey could not be verified.",
            )
        })?;
    let lock = state.auth.user_lock(&username);
    let (_guards, held) = state.auth.lock_with_admin(&[&lock]).await;
    let held = held.map_err(|_| auth_busy_response())?;
    let mut user = state
        .auth
        .get_user(&username)
        .await
        .filter(|u| {
            u.verified
                && !u.disabled
                && (u.password_hash.as_str(), u.created_at)
                    == (
                        pending.password_verified.0.as_str(),
                        pending.password_verified.1,
                    )
        })
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))?;
    if !state.auth.account_ticket_live(&username, pending.epoch)
        || !state.auth.session_valid_now(&token, &username)
    {
        return Err(error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED));
    }
    let keys = user.passkeys.get_or_insert_with(|| Passkeys {
        handle: pending.handle,
        entries: vec![],
    });
    if keys.handle != pending.handle
        || keys.entries.len() >= MAX_PASSKEYS
        || keys
            .entries
            .iter()
            .any(|e| e.credential.cred_id() == credential.cred_id())
    {
        return Err(error(
            StatusCode::CONFLICT,
            "The passkey list changed. Start again.",
        ));
    }
    keys.entries.push(Entry {
        id: Uuid::new_v4(),
        name: pending.name,
        credential,
        counter: 0,
        added_at: chrono::Utc::now().timestamp(),
    });
    state
        .auth
        .write_user_atomic(&held, &username, &user)
        .await
        .map_err(|_| auth_busy_response())?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Remove {
    id: Uuid,
}

async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Remove>,
) -> Result<StatusCode, Response> {
    get_webauthn(&state, &headers)?;
    let (username, token) = account(&state, &headers)?;
    let lock = state.auth.user_lock(&username);
    let (_guards, held) = state.auth.lock_with_admin(&[&lock]).await;
    let held = held.map_err(|_| auth_busy_response())?;
    let mut user = state
        .auth
        .get_user(&username)
        .await
        .filter(|u| u.verified && !u.disabled)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))?;
    if !state.auth.session_valid_now(&token, &username) {
        return Err(error(StatusCode::UNAUTHORIZED, SESSION_EXPIRED));
    }
    if let Some(keys) = user.passkeys.as_mut() {
        keys.entries.retain(|e| e.id != body.id);
        if keys.entries.is_empty() {
            user.passkeys = None;
        }
        state
            .auth
            .write_user_atomic(&held, &username, &user)
            .await
            .map_err(|_| auth_busy_response())?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn login_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, Response> {
    let webauthn = get_webauthn(&state, &headers)?;
    check_login_rate(&state, &headers, "passkey_start")?;
    let (options, authentication) = webauthn
        .start_discoverable_authentication()
        .map_err(|_| auth_busy_response())?;
    let pending = PendingLogin { authentication };
    let id = state
        .passkeys
        .start(Ceremony::Login(Box::new(pending)))
        .ok_or_else(auth_busy_response)?;
    Ok(Json(json!({"id": id, "options": options})))
}

fn check_login_rate(state: &AppState, headers: &HeaderMap, action: &str) -> Result<(), Response> {
    if state
        .auth
        .check_ip_rate_limit(action, client_ip(headers).as_deref())
        .is_err()
    {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again shortly.",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct LoginFinish {
    id: Uuid,
    username: String,
    credential: PublicKeyCredential,
}

async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginFinish>,
) -> Result<Json<AuthOkBody>, Response> {
    let webauthn = get_webauthn(&state, &headers)?;
    check_login_rate(&state, &headers, "passkey_finish")?;
    let refuse = || error(StatusCode::UNAUTHORIZED, LOGIN_FAILED);
    let Some(Ceremony::Login(pending)) = state.passkeys.take(body.id) else {
        return Err(refuse());
    };
    let (handle, credential_id) = webauthn
        .identify_discoverable_authentication(&body.credential)
        .map_err(|_| refuse())?;
    if body.username.len() > 320 {
        return Err(refuse());
    }
    let username = if body.username.trim().is_empty() {
        let _permit = state
            .passkeys
            .account_scans
            .try_acquire()
            .map_err(|_| auth_busy_response())?;
        find_account_by_handle(&state, handle)
            .await
            .ok_or_else(refuse)?
    } else if body.username.contains('@') {
        let _permit = state
            .passkeys
            .account_scans
            .try_acquire()
            .map_err(|_| auth_busy_response())?;
        state.auth.canonical_login_id(&body.username).await
    } else {
        body.username.trim().to_ascii_lowercase()
    };
    if !auth::is_safe_username(&username) {
        return Err(refuse());
    }
    let lock = state.auth.user_lock(&username);
    let (_guards, held) = state.auth.lock_with_admin(&[&lock]).await;
    let held = held.map_err(|_| auth_busy_response())?;
    let epoch = state.auth.account_epoch(&username);
    let mut user = state
        .auth
        .get_user(&username)
        .await
        .filter(|u| u.verified && !u.disabled)
        .ok_or_else(refuse)?;
    let keys = user
        .passkeys
        .as_mut()
        .filter(|k| k.handle == handle)
        .ok_or_else(refuse)?;
    let entry = keys
        .entries
        .iter_mut()
        .find(|e| e.credential.cred_id().as_slice() == credential_id)
        .ok_or_else(refuse)?;
    let result = webauthn
        .finish_discoverable_authentication(
            &body.credential,
            pending.authentication,
            &[DiscoverableKey::from(&entry.credential)],
        )
        .map_err(|_| refuse())?;
    if !result.user_verified()
        || ((entry.counter != 0 || result.counter() != 0) && result.counter() <= entry.counter)
    {
        return Err(refuse());
    }
    entry.credential.update_credential(&result);
    entry.counter = result.counter();
    user.last_login = chrono::Utc::now().timestamp();
    state
        .auth
        .write_user_atomic(&held, &username, &user)
        .await
        .map_err(|_| auth_busy_response())?;
    let token = state
        .auth
        .issue_session_if_live(&username, epoch)
        .ok_or_else(refuse)?;
    Ok(Json(AuthOkBody { token, username }))
}

async fn find_account_by_handle(state: &AppState, handle: Uuid) -> Option<String> {
    let path = std::path::Path::new(&state.data_dir).join("users");
    let mut entries = tokio::fs::read_dir(path).await.ok()?;
    while let Some(entry) = entries.next_entry().await.ok()? {
        let path = entry.path();
        let Some(username) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.extension().is_some_and(|ext| ext == "json")
            && auth::is_safe_username(username)
            && state
                .auth
                .get_user(username)
                .await
                .is_some_and(|user| user.passkeys.is_some_and(|keys| keys.handle == handle))
        {
            return Some(username.to_owned());
        }
    }
    None
}
