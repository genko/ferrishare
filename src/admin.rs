//! Handlers and endpoints for site-wide adminstration, including login, logout and dashboard

use std::{collections::HashMap, str::FromStr};

use argon2::{password_hash::PasswordVerifier, Argon2, PasswordHash};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    Form, Json,
};
use axum_extra::extract::CookieJar;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{prelude::Utc, DateTime, TimeDelta};
use cookie::{time::Duration, Cookie};
use minify_html::minify;
use rand::{prelude::*, rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use crate::download::pretty_print_delta;
use crate::*;

/// Handler for the site-wide administration page, serving the login form or admin dashboard.
pub async fn admin_page(
    Query(params): Query<HashMap<String, String>>,
    State(aps): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    // Calculate the base64url-encoded sha256sum of the session cookie, if any.
    let user_session_sha256sum = URL_SAFE_NO_PAD.encode(Sha256::digest(
        URL_SAFE_NO_PAD
            .decode(jar.get("id").map_or("", |e| e.value()))
            .unwrap_or_default(),
    ));

    let session_expiry: Option<String> = sqlx::query_scalar(
        "SELECT expiry_ts FROM admin_sessions WHERE session_id_sha256sum = ? LIMIT 1;",
    )
    .bind(&user_session_sha256sum)
    .fetch_optional(&aps.db)
    .await?;

    // Only show the admin page if the session exists and has not yet expired.
    if !session_expiry.map_or(Ok(true), |v| has_expired(&v))? {
        #[derive(FromRow)]
        struct FileRow {
            efd_sha256sum: String,
            filesize: i64,
            upload_ip: String,
            upload_ts: String,
            expiry_ts: String,
            downloads: i64,
        }
        // Request info about all currently live files.
        let all_files: Vec<FileRow> = sqlx::query_as(
            "SELECT efd_sha256sum, filesize, upload_ip, upload_ts, expiry_ts, downloads FROM uploaded_files;",
        )
        .fetch_all(&aps.db)
        .await?;

        // Filter out files that have technically expired but were not yet cleaned up by the
        // automatic cleanup task.
        let all_files = all_files
            .into_iter()
            .filter(|e| !has_expired(&e.expiry_ts).unwrap_or(false))
            .collect::<Vec<_>>();

        // Determine how much storage space all uploaded files currently use.
        let used_quota: u64 = all_files.iter().map(|e| e.filesize as u64).sum();

        #[derive(FromRow)]
        struct TokenRow {
            id: i64,
            token_sha256sum: String,
            created_ts: String,
            used_ts: Option<String>,
            used_by_ip: Option<String>,
        }

        // Request info about all upload tokens
        let all_tokens: Vec<TokenRow> = sqlx::query_as(
            "SELECT id, token_sha256sum, created_ts, used_ts, used_by_ip FROM upload_tokens;",
        )
        .fetch_all(&aps.db)
        .await?;

        #[derive(Debug, Serialize)]
        struct UploadedFile {
            efd_sha256sum: String,
            formatted_filesize: String,
            upload_ip_pretty: String,
            upload_ts_pretty: String,
            upload_ts: String,
            expiry_ts_pretty: String,
            expiry_ts: String,
            downloads: i64,
        }

        let now = Utc::now();

        // Transform the database rows into pretty strings
        // that can be templated into the dashboard.
        let ufs = all_files
            .into_iter()
            .map(|e| {
                let uts = DateTime::parse_from_rfc3339(&e.upload_ts).ok();
                let ets = DateTime::parse_from_rfc3339(&e.expiry_ts).ok();
                UploadedFile {
                    efd_sha256sum: e.efd_sha256sum,
                    formatted_filesize: pretty_print_bytes(e.filesize as u64),
                    upload_ip_pretty: {
                        IpPrefix::from_str(&e.upload_ip)
                            .map(|v| v.pretty_print())
                            .unwrap_or_else(|_| "(invalid IP)".into())
                    },
                    upload_ts_pretty: if let Some(uts) = uts {
                        format!("{} ago", pretty_print_delta(now, uts))
                    } else {
                        "N/A".to_string()
                    },
                    upload_ts: if let Some(uts) = uts {
                        uts.format("(%c)").to_string()
                    } else {
                        "(invalid timestamp)".to_string()
                    },
                    expiry_ts_pretty: if let Some(ets) = ets {
                        pretty_print_delta(now, ets)
                    } else {
                        "N/A".to_string()
                    },
                    expiry_ts: if let Some(ets) = ets {
                        ets.format("(%c)").to_string()
                    } else {
                        "(invalid timestamp)".to_string()
                    },
                    downloads: e.downloads,
                }
            })
            .collect::<Vec<_>>();

        #[derive(Debug, Serialize)]
        struct UploadToken {
            id: i64,
            token_sha256sum_short: String,
            created_ts_pretty: String,
            created_ts: String,
            used: bool,
            used_ts_pretty: String,
            used_ts: String,
            used_by_ip_pretty: String,
        }

        // Transform the token database rows into pretty strings
        let tokens = all_tokens
            .into_iter()
            .map(|t| {
                let cts = DateTime::parse_from_rfc3339(&t.created_ts).ok();
                let uts = t.used_ts.as_ref().and_then(|ts| DateTime::parse_from_rfc3339(ts).ok());
                UploadToken {
                    id: t.id,
                    token_sha256sum_short: t.token_sha256sum.chars().take(16).collect(),
                    created_ts_pretty: if let Some(cts) = cts {
                        format!("{} ago", pretty_print_delta(now, cts))
                    } else {
                        "N/A".to_string()
                    },
                    created_ts: if let Some(cts) = cts {
                        cts.format("(%c)").to_string()
                    } else {
                        "(invalid timestamp)".to_string()
                    },
                    used: t.used_ts.is_some(),
                    used_ts_pretty: if let Some(uts) = uts {
                        format!("{} ago", pretty_print_delta(now, uts))
                    } else {
                        "N/A".to_string()
                    },
                    used_ts: if let Some(uts) = uts {
                        uts.format("(%c)").to_string()
                    } else {
                        "".to_string()
                    },
                    used_by_ip_pretty: t.used_by_ip.as_ref().map_or("N/A".to_string(), |ip| {
                        IpPrefix::from_str(ip)
                            .map(|v| v.pretty_print())
                            .unwrap_or_else(|_| "(invalid IP)".into())
                    }),
                }
            })
            .collect::<Vec<_>>();

        // Add the global statistics to the rendering context.
        let mut context = aps.default_context();
        context.insert("files", &ufs);
        context.insert("tokens", &tokens);
        context.insert("full_file_count", &ufs.len());
        context.insert("maximum_quota", &pretty_print_bytes(aps.conf.maximum_quota));
        context.insert("used_quota", &pretty_print_bytes(used_quota));
        // And actually render.
        let h = aps.tera.render("admin_overview.html", &context)?;
        Ok(Html(String::from_utf8(minify(h.as_bytes(), &MINIFY_CFG))?))
    } else {
        // Check if this is a normal visit or a Redirect from a failed login-attempt.
        let failed_login = params.get("status").map_or(false, |e| e == "login_failed");

        // If the client is not logged in, serve the login form.
        let mut context = aps.default_context();
        context.insert("failed_login", &failed_login);
        let h = aps.tera.render("admin_login.html", &context)?;
        Ok(Html(String::from_utf8(minify(h.as_bytes(), &MINIFY_CFG))?))
    }
}

#[derive(Debug, Deserialize)]
pub struct AdminLogin {
    password: String,
    long_login: Option<String>,
}

/// Endpoint allowing a site-wide administrator to login with a POST request
pub async fn admin_login(
    State(aps): State<AppState>,
    jar: CookieJar,
    Form(admin_login): Form<AdminLogin>,
) -> Result<(CookieJar, Redirect), AppError> {
    // Parse the config's PasswordHash
    let admin_pw = PasswordHash::new(&aps.conf.admin_password_hash).map_err(|e| {
        AppError::new500(format!(
            "the admin password hash in config.toml could not be parsed correctly: {e}"
        ))
    })?;

    // Verify the provided password.
    let password_result =
        Argon2::default().verify_password(admin_login.password.as_bytes(), &admin_pw);

    if password_result.is_err() {
        return Ok((jar, Redirect::to("/admin?status=login_failed")));
    }

    // Create a new session.
    let session_id_bytes = rng().random::<[u8; 32]>();
    let session_id = URL_SAFE_NO_PAD.encode(session_id_bytes);

    // Use the sha256-digest in the databse.
    let session_id_sha256sum = URL_SAFE_NO_PAD.encode(Sha256::digest(session_id_bytes));

    // Build the cookie for the session id.
    let mut session_cookie = Cookie::build(("id", session_id))
        .http_only(true)
        .secure(true)
        .same_site(cookie::SameSite::Strict);

    // If a long session is requested, it will be given 30 days validity.
    // Otherwise, it will be given 24 hours validity and
    // the cookie will be set to expire on closing the browser.

    if admin_login.long_login.is_some() {
        session_cookie = session_cookie.max_age(Duration::days(30));
    }

    // Session validity is either one or 30 days, depending on the login checkbox.
    let duration_days = admin_login.long_login.map_or(1, |_| 30);
    // Calculate the RFC3339 timestamp for session expiry, either in one or 30 days.
    let expiry_ts = Utc::now()
        .checked_add_signed(TimeDelta::days(duration_days))
        .ok_or_else(|| AppError::new500("failed to apply duration to current timestamp"))?
        .to_rfc3339();

    sqlx::query("INSERT INTO admin_sessions (session_id_sha256sum, expiry_ts) VALUES (?, ?);")
        .bind(&session_id_sha256sum)
        .bind(&expiry_ts)
        .execute(&aps.db)
        .await?;

    tracing::info!(session_id_sha256sum, duration_days, "new admin login");

    Ok((jar.add(session_cookie), Redirect::to("/admin")))
}

/// Endpoint allowing a site-wide administrator to manually logout
pub async fn admin_logout(
    State(aps): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), AppError> {
    // Calculate the base64url-encoded sha256sum of the session cookie, if any.
    let user_session_sha256sum = URL_SAFE_NO_PAD.encode(Sha256::digest(
        URL_SAFE_NO_PAD
            .decode(jar.get("id").map_or("", |e| e.value()))
            .unwrap_or_default(),
    ));

    // Remove whatever rows exist with that sha256sum.
    let db_results = sqlx::query("DELETE FROM admin_sessions WHERE session_id_sha256sum = ?;")
        .bind(&user_session_sha256sum)
        .execute(&aps.db)
        .await?;

    tracing::info!(
        user_session_sha256sum,
        "logging out {0} admin session(s)",
        db_results.rows_affected()
    );

    Ok((jar.remove("id"), Redirect::to("/admin")))
}

/// Endpoint allowing a site-wide administrator to create a new one-time upload token
pub async fn create_upload_token(
    State(aps): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    // Verify the admin is logged in
    let user_session_sha256sum = URL_SAFE_NO_PAD.encode(Sha256::digest(
        URL_SAFE_NO_PAD
            .decode(jar.get("id").map_or("", |e| e.value()))
            .unwrap_or_default(),
    ));

    let session_expiry: Option<String> = sqlx::query_scalar(
        "SELECT expiry_ts FROM admin_sessions WHERE session_id_sha256sum = ? LIMIT 1;",
    )
    .bind(&user_session_sha256sum)
    .fetch_optional(&aps.db)
    .await?;

    // Check if the session exists and has not yet expired.
    if session_expiry.map_or(Ok(true), |v| has_expired(&v))? {
        return AppError::err(StatusCode::UNAUTHORIZED, "not logged in");
    }

    // Generate a random token out of 256 bits of strong entropy
    let token_bytes = rng().random::<[u8; 32]>();
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    // Hash the token for storage in the database
    let token_sha256sum = URL_SAFE_NO_PAD.encode(Sha256::digest(token_bytes));

    // Get the current timestamp
    let created_ts = Utc::now().to_rfc3339();

    // Insert the token into the database
    sqlx::query("INSERT INTO upload_tokens (token_sha256sum, created_ts) VALUES (?, ?);")
        .bind(&token_sha256sum)
        .bind(&created_ts)
        .execute(&aps.db)
        .await?;

    tracing::info!(token_sha256sum, "created new upload token");

    // Return the token in JSON format
    Ok(Json(CreateTokenResponse { token }))
}

#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    token: String,
}

/// Endpoint allowing a site-wide administrator to delete an upload token
#[derive(Debug, Deserialize)]
pub struct DeleteTokenRequest {
    token_id: i64,
}

pub async fn delete_upload_token(
    State(aps): State<AppState>,
    jar: CookieJar,
    Json(req): Json<DeleteTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Verify the admin is logged in
    let user_session_sha256sum = URL_SAFE_NO_PAD.encode(Sha256::digest(
        URL_SAFE_NO_PAD
            .decode(jar.get("id").map_or("", |e| e.value()))
            .unwrap_or_default(),
    ));

    let session_expiry: Option<String> = sqlx::query_scalar(
        "SELECT expiry_ts FROM admin_sessions WHERE session_id_sha256sum = ? LIMIT 1;",
    )
    .bind(&user_session_sha256sum)
    .fetch_optional(&aps.db)
    .await?;

    // Check if the session exists and has not yet expired.
    if session_expiry.map_or(Ok(true), |v| has_expired(&v))? {
        return AppError::err(StatusCode::UNAUTHORIZED, "not logged in");
    }

    // Delete the token
    let result = sqlx::query("DELETE FROM upload_tokens WHERE id = ?;")
        .bind(req.token_id)
        .execute(&aps.db)
        .await?;

    if result.rows_affected() == 0 {
        return AppError::err(StatusCode::NOT_FOUND, "token not found");
    }

    tracing::info!(token_id = req.token_id, "deleted upload token");

    Ok(StatusCode::OK)
}
