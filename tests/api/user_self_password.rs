//! U8a: self-service password change via `PUT /api/dashboard/auth/me`.

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use monoize::app::{RuntimeConfig, build_app, load_state_with_runtime};
use monoize::users::UserRole;
use serde_json::{Value, json};
use tower::ServiceExt;

struct PasswordTestContext {
    router: axum::Router,
    auth_header: String,
}

async fn setup_self_password() -> PasswordTestContext {
    let state = load_state_with_runtime(RuntimeConfig {
        listen: "127.0.0.1:0".to_string(),
        metrics_path: "/metrics".to_string(),
        database_dsn: "sqlite::memory:".to_string(),
        request_log_spool_dir: None,
        node: monoize::node_config::NodeSettings::primary_default(),
    })
    .await
    .expect("state loads");
    let user = state
        .user_store
        .create_user("self_password_user", "original-password", UserRole::User, &[])
        .await
        .expect("user created");
    let session = state
        .user_store
        .create_session(&user.id, 7)
        .await
        .expect("session created");

    PasswordTestContext {
        router: build_app(state),
        auth_header: format!("Bearer {}", session.token),
    }
}

async fn send_json(
    ctx: &PasswordTestContext,
    method: Method,
    path: &str,
    authorized: bool,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(CONTENT_TYPE, "application/json");
    if authorized {
        builder = builder.header(AUTHORIZATION, ctx.auth_header.clone());
    }
    let resp = ctx
        .router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, value)
}

async fn login_status(ctx: &PasswordTestContext, password: &str) -> StatusCode {
    let (status, _) = send_json(
        ctx,
        Method::POST,
        "/api/dashboard/auth/login",
        false,
        json!({ "username": "self_password_user", "password": password }),
    )
    .await;
    status
}

#[tokio::test]
async fn self_password_change_requires_verified_current_password() {
    let ctx = setup_self_password().await;

    // Too-short new password fails before any credential check.
    let (status, body) = send_json(
        &ctx,
        Method::PUT,
        "/api/dashboard/auth/me",
        true,
        json!({ "password": "short", "current_password": "original-password" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_password");

    // Missing current password is rejected.
    let (status, body) = send_json(
        &ctx,
        Method::PUT,
        "/api/dashboard/auth/me",
        true,
        json!({ "password": "brand-new-password" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_password");

    // Wrong current password is rejected and nothing is applied.
    let (status, body) = send_json(
        &ctx,
        Method::PUT,
        "/api/dashboard/auth/me",
        true,
        json!({
            "password": "brand-new-password",
            "current_password": "not-the-password",
            "email": "should-not-apply@example.com"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "invalid_credentials");
    assert_eq!(login_status(&ctx, "original-password").await, StatusCode::OK);

    // Correct current password swaps the credential.
    let (status, body) = send_json(
        &ctx,
        Method::PUT,
        "/api/dashboard/auth/me",
        true,
        json!({
            "password": "brand-new-password",
            "current_password": "original-password"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "self_password_user");
    assert_eq!(
        login_status(&ctx, "brand-new-password").await,
        StatusCode::OK
    );
    assert_eq!(
        login_status(&ctx, "original-password").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn email_only_update_still_works_without_password_fields() {
    let ctx = setup_self_password().await;
    let (status, body) = send_json(
        &ctx,
        Method::PUT,
        "/api/dashboard/auth/me",
        true,
        json!({ "email": "self@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "self@example.com");
}
