//! Authenticated-mode support: everything the reference server does with
//! Hypixel's auth/session services so the retail client will talk to us.
//! The retail client refuses the insecure (development) handshake, so a
//! real server must:
//!   1. Log ITSELF in once (OAuth device flow, client_id "hytale-server")
//!      and create a game session, yielding a session token + server
//!      identity token. Stored in auth.json and refreshed as needed.
//!   2. Validate each connecting client's identity JWT (EdDSA signature
//!      against the session service JWKS, issuer, timestamps, scope).
//!   3. Run the mutual-auth exchange: request an authorization grant for
//!      the client's identity token, hand it to the client, validate the
//!      client's access token, and exchange the client's grant for a
//!      server access token.
//!
//! Endpoints and payloads mirror AuthConfig / SessionServiceClient /
//! OAuthClient in the shared server source. Tokens are credentials:
//! they are never logged, and the auth file is written 0600 on unix.

use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const CLIENT_ID: &str = "hytale-server";
pub const SCOPES: &str = "openid offline auth:server";
pub const SCOPE_CLIENT: &str = "hytale:client";
/// The reference JWTValidator tolerates 5 minutes of clock skew.
pub const CLOCK_SKEW_SECONDS: i64 = 300;

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|e| format!("base64url decode: {e}"))
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 of the certificate DER, base64url without padding — the
/// x509Fingerprint format the session service expects (CertificateUtil).
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(cert_der);
    b64url_encode(&h.finalize())
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Generate a random-looking UUID string (v4 layout) from time + pid +
/// counter hashed together. Only used as the server session id (the
/// audience for auth grants), where the reference also uses a fresh
/// random UUID per boot.
pub fn new_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = Sha256::new();
    h.update(now_unix().to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    crate::format_uuid(&b)
}

/// Parse an ISO-8601 instant ("2026-10-24T07:00:00.123Z" / with offset)
/// to unix seconds. Returns None on anything unexpected.
pub fn parse_instant(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once('T')?;
    let mut dp = date.split('-');
    let year: i64 = dp.next()?.parse().ok()?;
    let month: i64 = dp.next()?.parse().ok()?;
    let day: i64 = dp.next()?.parse().ok()?;
    let (time, offset_secs) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0i64)
    } else if let Some(idx) = rest.rfind(['+', '-']) {
        if idx == 0 {
            return None;
        }
        let off = &rest[idx..];
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let mut op = off[1..].split(':');
        let oh: i64 = op.next()?.parse().ok()?;
        let om: i64 = op.next().unwrap_or("0").parse().ok()?;
        (&rest[..idx], sign * (oh * 3600 + om * 60))
    } else {
        (rest, 0)
    };
    let t = time.split('.').next()?;
    let mut tp = t.split(':');
    let hh: i64 = tp.next()?.parse().ok()?;
    let mm: i64 = tp.next()?.parse().ok()?;
    let ss: i64 = tp.next().unwrap_or("0").parse().ok()?;
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss - offset_secs)
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub oauth_token: String,
    pub device_auth: String,
    pub sessions: String,
    pub account_data: String,
}

impl Endpoints {
    pub fn for_domain(domain: &str) -> Self {
        Endpoints {
            oauth_token: format!("https://oauth.accounts.{domain}/oauth2/token"),
            device_auth: format!("https://oauth.accounts.{domain}/oauth2/device/auth"),
            sessions: format!("https://sessions.{domain}"),
            account_data: format!("https://account-data.{domain}"),
        }
    }

    /// The session service URL doubles as the JWT issuer.
    pub fn issuer(&self) -> &str {
        &self.sessions
    }
}

#[derive(Debug, Clone)]
pub struct IdentityClaims {
    pub uuid: String,
    pub username: String,
    pub skin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccessClaims {
    pub uuid: String,
    pub username: String,
}

#[derive(Clone)]
struct Jwk {
    kid: String,
    key: [u8; 32],
}

fn parse_jwks(doc: &Value) -> Vec<Jwk> {
    let mut out = Vec::new();
    if let Some(keys) = doc.get("keys").and_then(|k| k.as_array()) {
        for k in keys {
            if k.get("kty").and_then(|v| v.as_str()) != Some("OKP") {
                continue;
            }
            if k.get("crv").and_then(|v| v.as_str()) != Some("Ed25519") {
                continue;
            }
            let (Some(kid), Some(x)) = (
                k.get("kid").and_then(|v| v.as_str()),
                k.get("x").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            if let Ok(raw) = b64url_decode(x) {
                if raw.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&raw);
                    out.push(Jwk { kid: kid.to_string(), key });
                }
            }
        }
    }
    out
}

/// JWT validation mirroring the reference JWTValidator: EdDSA only,
/// signature from the session-service JWKS, issuer, timestamp window
/// with 5-minute skew; identity tokens additionally need the profile
/// claims and the hytale:client scope, access tokens a strict audience.
pub struct JwtValidator {
    issuer: String,
    keys: RwLock<Vec<Jwk>>,
    last_fetch: RwLock<Option<i64>>,
}

impl JwtValidator {
    pub fn new(issuer: String) -> Self {
        JwtValidator { issuer, keys: RwLock::new(Vec::new()), last_fetch: RwLock::new(None) }
    }

    pub fn key_count(&self) -> usize {
        self.keys.read().map(|k| k.len()).unwrap_or(0)
    }

    pub fn set_keys_from_jwks(&self, doc: &Value) {
        let keys = parse_jwks(doc);
        if let Ok(mut slot) = self.keys.write() {
            *slot = keys;
        }
        if let Ok(mut t) = self.last_fetch.write() {
            *t = Some(now_unix());
        }
    }

    /// Fetch the JWKS if we have none or it is more than 5 minutes old
    /// (the reference's minimum refresh interval).
    pub async fn maybe_refresh(&self, client: &reqwest::Client, sessions_url: &str) {
        let stale = {
            let last = self.last_fetch.read().map(|t| *t).unwrap_or(None);
            self.key_count() == 0 || last.map(|t| now_unix() - t > 300).unwrap_or(true)
        };
        if !stale {
            return;
        }
        match client.get(format!("{sessions_url}/.well-known/jwks.json")).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
                Ok(doc) => {
                    self.set_keys_from_jwks(&doc);
                    println!("[auth] JWKS loaded: {} signing keys", self.key_count());
                }
                Err(e) => eprintln!("[auth] JWKS response parse failed: {e}"),
            },
            Ok(resp) => eprintln!("[auth] JWKS fetch failed: HTTP {}", resp.status()),
            Err(e) => eprintln!("[auth] JWKS fetch failed: {e}"),
        }
    }

    /// Verify the signature and return (header, claims) JSON.
    fn verify(&self, token: &str) -> Result<(Value, Value), String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("not a three-part JWT".into());
        }
        let header: Value =
            serde_json::from_slice(&b64url_decode(parts[0])?).map_err(|e| format!("JWT header: {e}"))?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
            return Err(format!("unsupported JWT alg: {:?}", header.get("alg")));
        }
        let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("");
        let claims: Value =
            serde_json::from_slice(&b64url_decode(parts[1])?).map_err(|e| format!("JWT claims: {e}"))?;
        let sig_bytes = b64url_decode(parts[2])?;
        if sig_bytes.len() != 64 {
            return Err("JWT signature is not 64 bytes".into());
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let keys = self.keys.read().map_err(|_| "jwks lock".to_string())?;
        let candidates: Vec<&Jwk> = if kid.is_empty() {
            keys.iter().collect()
        } else {
            keys.iter().filter(|k| k.kid == kid).collect()
        };
        if candidates.is_empty() {
            return Err(format!("no JWKS key for kid {kid:?} (have {} keys)", keys.len()));
        }
        for k in candidates {
            if let Ok(vk) = VerifyingKey::from_bytes(&k.key) {
                if vk.verify(signing_input.as_bytes(), &signature).is_ok() {
                    return Ok((header, claims));
                }
            }
        }
        Err("JWT signature verification failed".into())
    }

    fn check_issuer_and_times(&self, claims: &Value) -> Result<(), String> {
        let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if iss != self.issuer {
            return Err(format!("issuer mismatch: expected {}, got {iss}", self.issuer));
        }
        let now = now_unix();
        let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or("missing exp claim")?;
        if now >= exp + CLOCK_SKEW_SECONDS {
            return Err(format!("token expired (exp {exp}, now {now})"));
        }
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if now < nbf - CLOCK_SKEW_SECONDS {
                return Err("token not yet valid (nbf)".into());
            }
        }
        if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
            if iat > now + CLOCK_SKEW_SECONDS {
                return Err("token issued in the future (iat)".into());
            }
        }
        Ok(())
    }

    pub fn validate_identity(&self, token: &str) -> Result<IdentityClaims, String> {
        let (_, claims) = self.verify(token)?;
        self.check_issuer_and_times(&claims)?;
        let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
        if parse_uuid_str(sub).is_none() {
            return Err(format!("identity subject is not a UUID: {sub:?}"));
        }
        let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("");
        if !scope.split_whitespace().any(|s| s == SCOPE_CLIENT) {
            return Err(format!("identity token missing scope {SCOPE_CLIENT} (has {scope:?})"));
        }
        let profile = claims.get("profile").ok_or("identity token missing profile claim")?;
        let username = profile.get("username").and_then(|v| v.as_str()).unwrap_or("");
        if username.is_empty() {
            return Err("identity token profile missing username".into());
        }
        Ok(IdentityClaims {
            uuid: sub.to_string(),
            username: username.to_string(),
            skin: profile.get("skin").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }

    pub fn validate_access(&self, token: &str, expected_audience: &str) -> Result<AccessClaims, String> {
        let (_, claims) = self.verify(token)?;
        self.check_issuer_and_times(&claims)?;
        let aud = match claims.get("aud") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(a)) => {
                a.first().and_then(|v| v.as_str()).unwrap_or("").to_string()
            }
            _ => String::new(),
        };
        if aud != expected_audience {
            return Err(format!("audience mismatch: expected {expected_audience}, got {aud}"));
        }
        let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
        let username = claims.get("username").and_then(|v| v.as_str()).unwrap_or("");
        if sub.is_empty() || username.is_empty() {
            return Err("access token missing sub/username".into());
        }
        Ok(AccessClaims { uuid: sub.to_string(), username: username.to_string() })
    }
}

/// Server-side auth state: the server's own OAuth + game session, and
/// the two session-service calls the login exchange needs.
pub struct ServerAuth {
    client: reqwest::Client,
    endpoints: Endpoints,
    file_path: Option<std::path::PathBuf>,
    /// Audience for grants: a fresh UUID per server boot, like the
    /// reference's serverSessionId.
    pub server_session_id: String,
    state: RwLock<AuthState>,
}

#[derive(Default)]
struct AuthState {
    refresh_token: Option<String>,
    profile_uuid: Option<String>,
    profile_username: Option<String>,
    session_token: Option<String>,
    identity_token: Option<String>,
    session_expires_at: Option<i64>,
}

impl ServerAuth {
    pub fn identity_token(&self) -> Option<String> {
        self.state.read().ok().and_then(|s| s.identity_token.clone())
    }

    async fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: Value,
    ) -> Result<(u16, Value), String> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {bearer}"))
            .header("User-Agent", "HytaleServer/1.0 (Rustale)")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| format!("POST {url} body: {e}"))?;
        let value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok((status, value))
    }

    async fn post_form(&self, url: &str, fields: &[(&str, String)]) -> Result<(u16, Value), String> {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", "HytaleServer/1.0 (Rustale)")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| format!("POST {url} body: {e}"))?;
        let value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok((status, value))
    }

    fn save(&self) {
        let (Some(path), Ok(state)) = (&self.file_path, self.state.read()) else {
            return;
        };
        let doc = json!({
            "refreshToken": state.refresh_token,
            "profileUuid": state.profile_uuid,
            "profileUsername": state.profile_username,
            "sessionToken": state.session_token,
            "identityToken": state.identity_token,
            "sessionExpiresAt": state.session_expires_at,
        });
        if let Ok(text) = serde_json::to_string_pretty(&doc) {
            if std::fs::write(path, text).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    fn load(&self) {
        let Some(path) = &self.file_path else { return };
        let Ok(text) = std::fs::read_to_string(path) else { return };
        let Ok(doc) = serde_json::from_str::<Value>(&text) else { return };
        if let Ok(mut s) = self.state.write() {
            let get = |k: &str| doc.get(k).and_then(|v| v.as_str()).map(|v| v.to_string());
            s.refresh_token = get("refreshToken");
            s.profile_uuid = get("profileUuid");
            s.profile_username = get("profileUsername");
            s.session_token = get("sessionToken");
            s.identity_token = get("identityToken");
            s.session_expires_at = doc.get("sessionExpiresAt").and_then(|v| v.as_i64());
        }
    }

    /// Bring the server session up: reuse a stored fresh session, refresh
    /// or recreate it from the stored OAuth refresh token, or run the
    /// interactive device login on first use.
    pub async fn init(
        client: reqwest::Client,
        endpoints: Endpoints,
        file_path: Option<std::path::PathBuf>,
    ) -> Result<ServerAuth, String> {
        let auth = ServerAuth {
            client,
            endpoints,
            file_path,
            server_session_id: new_session_id(),
            state: RwLock::new(AuthState::default()),
        };
        // Direct token injection, mirroring the reference's env support.
        let env_session = std::env::var("HYTALE_SERVER_SESSION_TOKEN").unwrap_or_default();
        let env_identity = std::env::var("HYTALE_SERVER_IDENTITY_TOKEN").unwrap_or_default();
        if !env_session.is_empty() && !env_identity.is_empty() {
            println!("[auth] using server tokens from environment");
            if let Ok(mut s) = auth.state.write() {
                s.session_token = Some(env_session);
                s.identity_token = Some(env_identity);
                s.session_expires_at = Some(now_unix() + 3600);
            }
            return Ok(auth);
        }
        auth.load();
        auth.ensure_session().await?;
        Ok(auth)
    }

    fn session_fresh(&self) -> bool {
        let Ok(s) = self.state.read() else { return false };
        s.session_token.is_some()
            && s.identity_token.is_some()
            && s.session_expires_at.map(|e| e > now_unix() + 300).unwrap_or(false)
    }

    async fn ensure_session(&self) -> Result<(), String> {
        if self.session_fresh() {
            println!("[auth] reusing stored server session");
            return Ok(());
        }
        // Try a session refresh first (cheapest path).
        let old_session = self.state.read().ok().and_then(|s| s.session_token.clone());
        if let Some(token) = old_session {
            if self.refresh_game_session(&token).await.is_ok() {
                self.save();
                return Ok(());
            }
        }
        // Then OAuth: refresh token -> access token -> new game session.
        let refresh = self.state.read().ok().and_then(|s| s.refresh_token.clone());
        if let Some(refresh_token) = refresh {
            let access = self.oauth_refresh(&refresh_token).await?;
            self.create_game_session(&access).await?;
            self.save();
            return Ok(());
        }
        // First run: interactive device login.
        let tokens = self.device_login().await?;
        if let Ok(mut s) = self.state.write() {
            s.refresh_token = Some(tokens.1);
        }
        self.create_game_session(&tokens.0).await?;
        self.save();
        Ok(())
    }

    async fn refresh_game_session(&self, session_token: &str) -> Result<(), String> {
        // The reference sends no body at all.
        let resp = self
            .client
            .post(format!("{}/game-session/refresh", self.endpoints.sessions))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("User-Agent", "HytaleServer/1.0 (Rustale)")
            .send()
            .await
            .map_err(|e| format!("game-session/refresh: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| format!("game-session/refresh body: {e}"))?;
        if status != 200 {
            return Err(format!("game-session/refresh: HTTP {status}: {text}"));
        }
        let doc: Value = serde_json::from_str(&text).map_err(|e| format!("game-session/refresh parse: {e}"))?;
        self.store_game_session(&doc)
    }

    fn store_game_session(&self, doc: &Value) -> Result<(), String> {
        let session = doc.get("sessionToken").and_then(|v| v.as_str());
        let identity = doc.get("identityToken").and_then(|v| v.as_str());
        let (Some(session), Some(identity)) = (session, identity) else {
            return Err(format!("game session response missing tokens: {doc}"));
        };
        let expires = doc
            .get("expiresAt")
            .and_then(|v| v.as_str())
            .and_then(parse_instant)
            .unwrap_or(now_unix() + 3600);
        if let Ok(mut s) = self.state.write() {
            s.session_token = Some(session.to_string());
            s.identity_token = Some(identity.to_string());
            s.session_expires_at = Some(expires);
        }
        println!("[auth] server game session active (expires {})", doc.get("expiresAt").and_then(|v| v.as_str()).unwrap_or("?"));
        Ok(())
    }

    async fn create_game_session(&self, oauth_access_token: &str) -> Result<(), String> {
        // Resolve the game profile if we don't have one stored.
        let have_profile = self.state.read().map(|s| s.profile_uuid.is_some()).unwrap_or(false);
        if !have_profile {
            let resp = self
                .client
                .get(format!("{}/my-account/get-profiles", self.endpoints.account_data))
                .header("Authorization", format!("Bearer {oauth_access_token}"))
                .header("User-Agent", "HytaleServer/1.0 (Rustale)")
                .send()
                .await
                .map_err(|e| format!("get-profiles: {e}"))?;
            let doc: Value = resp.json().await.map_err(|e| format!("get-profiles body: {e}"))?;
            let profiles = doc.get("profiles").and_then(|p| p.as_array()).cloned().unwrap_or_default();
            let first = profiles.first().ok_or("account has no game profiles")?;
            let uuid = first.get("uuid").and_then(|v| v.as_str()).ok_or("profile missing uuid")?;
            let username = first.get("username").and_then(|v| v.as_str()).unwrap_or("");
            println!("[auth] using game profile {username} ({uuid})");
            if let Ok(mut s) = self.state.write() {
                s.profile_uuid = Some(uuid.to_string());
                s.profile_username = Some(username.to_string());
            }
        }
        let profile_uuid = self.state.read().ok().and_then(|s| s.profile_uuid.clone()).unwrap();
        let (status, doc) = self
            .post_json(
                &format!("{}/game-session/new", self.endpoints.sessions),
                oauth_access_token,
                json!({ "uuid": profile_uuid }),
            )
            .await?;
        if status != 200 && status != 201 {
            return Err(format!("game-session/new: HTTP {status}: {doc}"));
        }
        self.store_game_session(&doc)
    }

    async fn oauth_refresh(&self, refresh_token: &str) -> Result<String, String> {
        let (status, doc) = self
            .post_form(
                &self.endpoints.oauth_token,
                &[
                    ("grant_type", "refresh_token".to_string()),
                    ("client_id", CLIENT_ID.to_string()),
                    ("refresh_token", refresh_token.to_string()),
                ],
            )
            .await?;
        if status != 200 {
            return Err(format!("oauth refresh: HTTP {status}: {doc}"));
        }
        if let Some(new_refresh) = doc.get("refresh_token").and_then(|v| v.as_str()) {
            if let Ok(mut s) = self.state.write() {
                s.refresh_token = Some(new_refresh.to_string());
            }
        }
        doc.get("access_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("oauth refresh response missing access_token: {doc}"))
    }

    /// OAuth device flow: prints the verification URL + code for the
    /// operator, polls until they complete sign-in (up to expiry).
    async fn device_login(&self) -> Result<(String, String), String> {
        let (status, doc) = self
            .post_form(
                &self.endpoints.device_auth,
                &[("client_id", CLIENT_ID.to_string()), ("scope", SCOPES.to_string())],
            )
            .await?;
        if status != 200 {
            return Err(format!("device auth start: HTTP {status}: {doc}"));
        }
        let device_code = doc.get("device_code").and_then(|v| v.as_str()).ok_or("device response missing device_code")?.to_string();
        let user_code = doc.get("user_code").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let verification = doc
            .get("verification_uri_complete")
            .and_then(|v| v.as_str())
            .or_else(|| doc.get("verification_uri").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        let interval = doc.get("interval").and_then(|v| v.as_i64()).unwrap_or(5).max(2);
        let expires_in = doc.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(900);
        println!();
        println!("[auth] This server needs a one-time Hytale login (like the official server's /auth login).");
        println!("[auth] Open: {verification}");
        if !user_code.is_empty() {
            println!("[auth] Code:  {user_code}");
        }
        println!("[auth] Waiting for sign-in to complete...");
        let deadline = now_unix() + expires_in;
        let mut wait = interval;
        loop {
            tokio::time::sleep(Duration::from_secs(wait as u64)).await;
            if now_unix() > deadline {
                return Err("device login expired before sign-in completed".into());
            }
            let (status, doc) = self
                .post_form(
                    &self.endpoints.oauth_token,
                    &[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code".to_string()),
                        ("client_id", CLIENT_ID.to_string()),
                        ("device_code", device_code.clone()),
                    ],
                )
                .await?;
            if status == 200 {
                let access = doc.get("access_token").and_then(|v| v.as_str()).ok_or("token response missing access_token")?.to_string();
                let refresh = doc.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                println!("[auth] login complete");
                return Ok((access, refresh));
            }
            match doc.get("error").and_then(|v| v.as_str()).unwrap_or("") {
                "authorization_pending" => continue,
                "slow_down" => {
                    wait += 5;
                    continue;
                }
                other => return Err(format!("device login failed: HTTP {status}: error={other} body={doc}")),
            }
        }
    }

    async fn session_bearer(&self) -> Result<String, String> {
        if !self.session_fresh() {
            self.ensure_session().await?;
        }
        self.state
            .read()
            .ok()
            .and_then(|s| s.session_token.clone())
            .ok_or_else(|| "no server session token".to_string())
    }

    /// POST /server-join/auth-grant for a client's identity token.
    pub async fn request_auth_grant(&self, identity_token: &str) -> Result<String, String> {
        let bearer = self.session_bearer().await?;
        let (status, doc) = self
            .post_json(
                &format!("{}/server-join/auth-grant", self.endpoints.sessions),
                &bearer,
                json!({ "identityToken": identity_token, "aud": self.server_session_id }),
            )
            .await?;
        if status != 200 {
            return Err(format!("auth-grant: HTTP {status}: {doc}"));
        }
        doc.get("authorizationGrant")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("auth-grant response missing authorizationGrant: {doc}"))
    }

    /// POST /server-join/auth-token, exchanging the client's grant for
    /// the server access token sent back in ServerAuthToken.
    pub async fn exchange_server_grant(
        &self,
        authorization_grant: &str,
        x509_fingerprint: &str,
    ) -> Result<String, String> {
        let bearer = self.session_bearer().await?;
        let (status, doc) = self
            .post_json(
                &format!("{}/server-join/auth-token", self.endpoints.sessions),
                &bearer,
                json!({ "authorizationGrant": authorization_grant, "x509Fingerprint": x509_fingerprint }),
            )
            .await?;
        if status != 200 {
            return Err(format!("auth-token: HTTP {status}: {doc}"));
        }
        doc.get("accessToken")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("auth-token response missing accessToken: {doc}"))
    }
}

/// Parse a canonical UUID string into its 16 bytes.
pub fn parse_uuid_str(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn validator_with_key() -> (JwtValidator, SigningKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let doc = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key",
                "x": b64url_encode(signing.verifying_key().as_bytes()),
            }]
        });
        let v = JwtValidator::new("https://sessions.hytale.com".to_string());
        v.set_keys_from_jwks(&doc);
        (v, signing)
    }

    fn mint(signing: &SigningKey, claims: Value) -> String {
        let header = json!({ "alg": "EdDSA", "kid": "test-key", "typ": "JWT" });
        let h = b64url_encode(serde_json::to_string(&header).unwrap().as_bytes());
        let c = b64url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let input = format!("{h}.{c}");
        let sig = signing.sign(input.as_bytes());
        format!("{input}.{}", b64url_encode(&sig.to_bytes()))
    }

    fn base_claims() -> Value {
        json!({
            "iss": "https://sessions.hytale.com",
            "sub": "523acb87-5dc9-4bbf-a419-380486de4a84",
            "iat": now_unix(),
            "exp": now_unix() + 3600,
        })
    }

    #[test]
    fn identity_token_validates() {
        let (v, signing) = validator_with_key();
        let mut claims = base_claims();
        claims["scope"] = json!("hytale:client openid");
        claims["profile"] = json!({ "username": "jreoka", "skin": "{\"a\":1}" });
        let token = mint(&signing, claims);
        let id = v.validate_identity(&token).unwrap();
        assert_eq!(id.username, "jreoka");
        assert_eq!(id.uuid, "523acb87-5dc9-4bbf-a419-380486de4a84");
        assert_eq!(id.skin.as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn identity_token_rejects_bad_cases() {
        let (v, signing) = validator_with_key();
        // No client scope.
        let mut claims = base_claims();
        claims["scope"] = json!("openid");
        claims["profile"] = json!({ "username": "jreoka" });
        assert!(v.validate_identity(&mint(&signing, claims)).is_err());
        // Wrong issuer.
        let mut claims = base_claims();
        claims["iss"] = json!("https://evil.example");
        claims["scope"] = json!("hytale:client");
        claims["profile"] = json!({ "username": "jreoka" });
        assert!(v.validate_identity(&mint(&signing, claims)).is_err());
        // Expired.
        let mut claims = base_claims();
        claims["exp"] = json!(now_unix() - 10_000);
        claims["scope"] = json!("hytale:client");
        claims["profile"] = json!({ "username": "jreoka" });
        assert!(v.validate_identity(&mint(&signing, claims)).is_err());
        // Tampered payload (signature no longer matches).
        let mut claims = base_claims();
        claims["scope"] = json!("hytale:client");
        claims["profile"] = json!({ "username": "jreoka" });
        let good = mint(&signing, claims);
        let mut parts: Vec<&str> = good.split('.').collect();
        let forged = json!({ "iss": "https://sessions.hytale.com", "sub": "523acb87-5dc9-4bbf-a419-380486de4a84", "exp": now_unix() + 99999, "scope": "hytale:client", "profile": { "username": "admin" } });
        let forged_b64 = b64url_encode(serde_json::to_string(&forged).unwrap().as_bytes());
        parts[1] = &forged_b64;
        assert!(v.validate_identity(&parts.join(".")).is_err());
    }

    #[test]
    fn access_token_audience_checked() {
        let (v, signing) = validator_with_key();
        let mut claims = base_claims();
        claims["aud"] = json!("my-server-session");
        claims["username"] = json!("jreoka");
        let token = mint(&signing, claims);
        let access = v.validate_access(&token, "my-server-session").unwrap();
        assert_eq!(access.username, "jreoka");
        assert!(v.validate_access(&token, "other-server").is_err());
    }

    #[test]
    fn instant_parsing() {
        assert_eq!(parse_instant("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_instant("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_instant("2026-10-24T07:30:00.5Z"), Some(1792827000));
        assert_eq!(parse_instant("nonsense"), None);
    }

    #[test]
    fn fingerprint_format() {
        let fp = cert_fingerprint(b"not a cert");
        assert_eq!(fp.len(), 43); // 32 bytes, base64url, no padding
        assert!(!fp.contains(['+', '/', '=']));
    }
}
