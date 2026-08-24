use crate::app::AppState;
use crate::dashboard_handlers::session_helpers::{
    get_current_user, is_reserved_internal_username, is_valid_username,
};
use crate::error::{AppError, AppResult};
use crate::users::{
    BillingPlan, RegisterUserError, User, UserRole, UserStore, UserTodayUsage, format_nano_to_usd,
};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UserBillingPlanResponse {
    pub id: String,
    pub name: String,
    pub grant_amount_nano_usd: String,
    pub grant_amount_usd: String,
    pub schedule: String,
    pub allowed_groups: Vec<String>,
    pub enabled: bool,
}

impl From<BillingPlan> for UserBillingPlanResponse {
    fn from(plan: BillingPlan) -> Self {
        let nano = plan
            .grant_amount_nano_usd
            .parse::<i128>()
            .expect("UserStore must validate persisted plan amounts");
        Self {
            id: plan.id,
            name: plan.name,
            grant_amount_usd: format_nano_to_usd(nano),
            grant_amount_nano_usd: plan.grant_amount_nano_usd,
            schedule: plan.schedule,
            allowed_groups: plan.allowed_groups,
            enabled: plan.enabled,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub created_at: String,
    pub last_login_at: Option<String>,
    pub enabled: bool,
    pub balance_nano_usd: String,
    pub balance_usd: String,
    pub balance_unlimited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub allowed_groups: Vec<String>,
    pub billing_plan_id: Option<String>,
    pub next_grant_at: Option<String>,
    pub billing_plan: Option<UserBillingPlanResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub today_calls: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub today_cost_nano_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub today_cost_usd: Option<String>,
}

impl UserResponse {
    pub fn from_user(u: User, plan: Option<BillingPlan>, today: Option<&UserTodayUsage>) -> Self {
        let balance_nano = u
            .balance_nano_usd
            .parse::<i128>()
            .expect("UserStore must validate persisted user balances");
        let (today_calls, today_cost_nano_usd, today_cost_usd) = match today {
            Some(row) => (
                Some(row.today_calls),
                Some(row.today_cost_nano_usd.to_string()),
                Some(format_nano_to_usd(row.today_cost_nano_usd)),
            ),
            None => (None, None, None),
        };
        Self {
            id: u.id,
            username: u.username,
            role: u.role,
            created_at: u.created_at.to_rfc3339(),
            last_login_at: u.last_login_at.map(|d| d.to_rfc3339()),
            enabled: u.enabled,
            balance_usd: format_nano_to_usd(balance_nano),
            balance_nano_usd: u.balance_nano_usd,
            balance_unlimited: u.balance_unlimited,
            email: u.email,
            allowed_groups: u.allowed_groups,
            billing_plan_id: u.billing_plan_id,
            next_grant_at: u.next_grant_at.map(|d| d.to_rfc3339()),
            billing_plan: plan.map(UserBillingPlanResponse::from),
            today_calls,
            today_cost_nano_usd,
            today_cost_usd,
        }
    }
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self::from_user(u, None, None)
    }
}

pub async fn user_response_from_store(
    store: &UserStore,
    user: User,
) -> Result<UserResponse, String> {
    let plan = match user.billing_plan_id.as_deref() {
        Some(id) => store.get_billing_plan_by_id(id).await?,
        None => None,
    };
    Ok(UserResponse::from_user(user, plan, None))
}

fn map_user_response_error(error: String) -> AppError {
    AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
}

#[derive(Debug, Deserialize)]
pub struct UpdateMeRequest {
    pub email: Option<Option<String>>,
    /// U8a: optional self-service password change; requires `current_password`.
    pub password: Option<String>,
    pub current_password: Option<String>,
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> AppResult<impl IntoResponse> {
    let client_ip = extract_client_ip(&headers).unwrap_or_else(|| "unknown".to_string());
    if !state.auth_rate_limiter.check(&client_ip) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests, please try again later",
        ));
    }

    let user_store = &state.user_store;
    let settings_store = &state.settings_store;

    if !is_valid_username(&body.username) {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_username",
            "username must be 3-22 characters, only letters, digits and underscores",
        ));
    }

    if is_reserved_internal_username(&body.username) {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "reserved_username",
            "username prefix _monoize_ is reserved",
        ));
    }

    if body.password.len() < 8 {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            "password must be at least 8 characters",
        ));
    }

    let registration_enabled = settings_store
        .is_registration_enabled()
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let user = user_store
        .register_user_atomic(&body.username, &body.password, registration_enabled)
        .await
        .map_err(|error| match error {
            RegisterUserError::RegistrationDisabled => AppError::new(
                StatusCode::FORBIDDEN,
                "registration_disabled",
                "user registration is currently disabled",
            ),
            RegisterUserError::UsernameExists => AppError::new(
                StatusCode::CONFLICT,
                "username_exists",
                "username already exists",
            ),
            RegisterUserError::Storage(error) => {
                AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
            }
        })?;

    let session_ttl_days = state
        .settings_store
        .get_session_ttl_days()
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let session = user_store
        .create_session(&user.id, session_ttl_days)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let cookie = build_session_cookie(&session.token, session_ttl_days);
    let user = user_response_from_store(user_store, user)
        .await
        .map_err(map_user_response_error)?;
    let body = Json(AuthResponse {
        token: session.token,
        user,
    });
    Ok(([(axum::http::header::SET_COOKIE, cookie)], body).into_response())
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> AppResult<impl IntoResponse> {
    let client_ip = extract_client_ip(&headers).unwrap_or_else(|| "unknown".to_string());
    if !state.auth_rate_limiter.check(&client_ip) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests, please try again later",
        ));
    }

    let user_store = &state.user_store;
    if is_reserved_internal_username(&body.username) {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "reserved_username",
            "username prefix _monoize_ is reserved",
        ));
    }

    let user = user_store
        .get_user_by_username(&body.username)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?
        .ok_or_else(|| {
            AppError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            )
        })?;

    if !user.enabled {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "account_disabled",
            "your account has been disabled",
        ));
    }

    let valid = crate::users::UserStore::verify_password(&body.password, &user.password_hash)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    if !valid {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid username or password",
        ));
    }

    user_store.update_last_login(&user.id).await.ok();

    let session_ttl_days = state
        .settings_store
        .get_session_ttl_days()
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let session = user_store
        .create_session(&user.id, session_ttl_days)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let cookie = build_session_cookie(&session.token, session_ttl_days);
    let user = user_response_from_store(user_store, user)
        .await
        .map_err(map_user_response_error)?;
    let body = Json(AuthResponse {
        token: session.token,
        user,
    });
    Ok(([(axum::http::header::SET_COOKIE, cookie)], body).into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let token = crate::dashboard_handlers::session_helpers::extract_session_token(&headers)
        .ok_or_else(|| {
            AppError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing authorization header",
            )
        })?;

    let user_store = &state.user_store;

    user_store
        .delete_session(&token)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let clear_cookie = clear_session_cookie();
    Ok((
        [(axum::http::header::SET_COOKIE, clear_cookie)],
        Json(json!({ "success": true })),
    )
        .into_response())
}
pub async fn get_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let user = get_current_user(&headers, &state).await?;
    let response = user_response_from_store(&state.user_store, user)
        .await
        .map_err(map_user_response_error)?;
    Ok(Json(response))
}

pub async fn update_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateMeRequest>,
) -> AppResult<impl IntoResponse> {
    let user = get_current_user(&headers, &state).await?;

    let user_store = &state.user_store;

    // U8a: a password change is all-or-nothing for the whole request, so the
    // current-password check runs before any field is written.
    if let Some(ref password) = body.password {
        if password.len() < 8 {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "invalid_password",
                "password must be at least 8 characters",
            ));
        }
        let current = body
            .current_password
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_password",
                    "current_password is required to change password",
                )
            })?;
        let valid = crate::users::UserStore::verify_password(current, &user.password_hash)
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;
        if !valid {
            return Err(AppError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "current password is incorrect",
            ));
        }
    }

    user_store
        .update_user(
            &user.id,
            None,
            body.password.as_deref(),
            None,
            None,
            None,
            None,
            body.email.as_ref().map(|e| e.as_deref()),
            None,
        )
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?;

    let updated_user = user_store
        .get_user_by_id(&user.id)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e))?
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "not_found", "user not found"))?;

    let response = user_response_from_store(user_store, updated_user)
        .await
        .map_err(map_user_response_error)?;
    Ok(Json(response))
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    crate::client_ip::canonical_client_ip_from_headers(headers).map(|address| address.to_string())
}

fn build_session_cookie(token: &str, ttl_days: i64) -> String {
    let max_age = ttl_days.max(0) * 86400;
    format!("monoize_session={token}; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age={max_age}")
}

fn clear_session_cookie() -> String {
    "monoize_session=; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=0".to_string()
}
