    use super::helpers::{
        DEFAULT_SESSION_CLEANUP_INTERVAL_SECS, canonicalize_ip_whitelist,
        parse_api_key_batch_delete_limit, parse_group_ids_json, parse_positive_limit,
        parse_session_cleanup_interval_secs, sanitize_api_key_transforms,
        serialize_group_ids_json, validate_api_key_transforms,
    };
    use crate::db::DbPool;
    use crate::migration::Migrator;
    use crate::transforms::{Phase, TransformRuleConfig};
    use crate::users::{
        AdminUpdateUserInput, CreateApiKeyInput, CreateApiKeyWithLimitError, CreateGroupInput,
        RegisterUserError, RequestCaptureMode, RequestCaptureRetention, UserRole, UserStore,
    };
    use chrono::Utc;
    use sea_orm::{ConnectionTrait, Value as SeaValue};
    use sea_orm_migration::MigratorTrait;
    use serde_json::json;

    #[tokio::test(flavor = "current_thread")]
    async fn async_password_helpers_hash_and_verify_passwords() {
        let hash = UserStore::hash_password_async("correct-password")
            .await
            .expect("password hashes");

        assert!(
            UserStore::verify_password_async("correct-password", &hash)
                .await
                .expect("password verifies")
        );
        assert!(
            !UserStore::verify_password_async("wrong-password", &hash)
                .await
                .expect("password mismatch is not an error")
        );
    }

    #[test]
    fn api_key_batch_limit_parser_rejects_non_positive_values() {
        assert_eq!(parse_positive_limit(Some("399"), 400), 399);
        assert_eq!(parse_positive_limit(Some("0"), 400), 400);
        assert_eq!(parse_positive_limit(Some("-1"), 400), 400);
        assert_eq!(parse_positive_limit(Some("invalid"), 400), 400);
        assert_eq!(parse_api_key_batch_delete_limit(Some("401")), 400);
    }

    #[test]
    fn session_cleanup_interval_parser_requires_positive_whole_seconds() {
        assert_eq!(parse_session_cleanup_interval_secs(Some("17")), 17);
        for invalid in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some("invalid"),
            Some("18446744073709551616"),
        ] {
            assert_eq!(
                parse_session_cleanup_interval_secs(invalid),
                DEFAULT_SESSION_CLEANUP_INTERVAL_SECS
            );
        }
    }

    #[tokio::test]
    async fn transform_compatibility_migration_crosses_the_fixed_batch_boundary() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("transform-migration", "password", UserRole::User, None)
            .await
            .expect("user creates");
        for index in 0..305 {
            store
                .create_api_key(&user.id, &format!("key-{index}"), None)
                .await
                .expect("key creates");
        }
        let legacy = serde_json::to_string(&vec![TransformRuleConfig {
            transform: "remove_anthropic_billing_header".to_string(),
            enabled: true,
            models: None,
            phase: Phase::Request,
            config: json!({}),
        }])
        .unwrap();
        db.write()
            .await
            .execute(db.stmt("UPDATE api_keys SET transforms = $1", vec![legacy.into()]))
            .await
            .expect("legacy transforms seed");
        db.write()
            .await
            .execute(db.stmt(
                "DELETE FROM system_settings WHERE key = $1",
                vec!["migration.api_key_transform_rule_ids.v2".into()],
            ))
            .await
            .expect("migration marker clears");
        // Seed the obsolete v1 marker to verify the v2 completion transaction removes it.
        db.write()
            .await
            .execute(db.stmt(
                "INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, $3)",
                vec![
                    "migration.api_key_transform_rule_ids.v1".into(),
                    "complete".into(),
                    Utc::now().to_rfc3339().into(),
                ],
            ))
            .await
            .expect("obsolete marker seeds");

        store
            .migrate_transform_rule_ids()
            .await
            .expect("transforms migrate");
        let rows = db
            .read()
            .query_all(db.stmt("SELECT transforms FROM api_keys", vec![]))
            .await
            .expect("transforms query");
        assert_eq!(rows.len(), 305);
        for row in rows {
            let raw: String = row.try_get("", "transforms").expect("transforms decode");
            let transforms: Vec<TransformRuleConfig> =
                serde_json::from_str(&raw).expect("transforms parse");
            assert_eq!(transforms[0].transform, "prompt_strip_anthropic_billing_header");
        }
        let markers = db
            .read()
            .query_all(db.stmt(
                "SELECT key, value FROM system_settings WHERE key LIKE 'migration.api_key_transform_rule_ids.%'",
                vec![],
            ))
            .await
            .expect("markers query");
        assert_eq!(markers.len(), 1);
        let marker_key: String = markers[0].try_get("", "key").expect("marker key");
        let marker_value: String = markers[0].try_get("", "value").expect("marker value");
        assert_eq!(marker_key, "migration.api_key_transform_rule_ids.v2");
        assert_eq!(marker_value, "complete");
    }

    #[tokio::test]
    async fn update_last_login_invalidates_cached_user_for_api_keys() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("last-login-cache", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let (_, token) = store
            .create_api_key(&user.id, "cached-key", None)
            .await
            .expect("key creates");

        let (_, cached_user, _) = store
            .validate_api_key(&token)
            .await
            .expect("initial validation succeeds")
            .expect("key is valid");
        assert!(cached_user.last_login_at.is_none());
        assert!(store.api_key_cache.get(&token).is_some());

        store
            .update_last_login(&user.id)
            .await
            .expect("last login updates");
        assert!(store.api_key_cache.get(&token).is_none());
        let (_, refreshed_user, _) = store
            .validate_api_key(&token)
            .await
            .expect("refreshed validation succeeds")
            .expect("key remains valid");
        assert!(refreshed_user.last_login_at.is_some());
    }

    #[tokio::test]
    async fn persisted_auth_policy_corruption_returns_error_without_caching() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("corrupt-policy", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let (api_key, token) = store
            .create_api_key(&user.id, "corrupt-policy-key", None)
            .await
            .expect("key creates");

        let api_key_cases: Vec<(&str, SeaValue, SeaValue)> = vec![
            (
                "model_limits",
                SeaValue::Int(Some(7)),
                "[]".to_string().into(),
            ),
            (
                "ip_whitelist",
                r#"["not-an-ip"]"#.to_string().into(),
                "[]".to_string().into(),
            ),
            (
                "group_ids",
                "{".to_string().into(),
                "[]".to_string().into(),
            ),
            (
                "transforms",
                "{".to_string().into(),
                "[]".to_string().into(),
            ),
            (
                "model_redirects",
                r#"[{"pattern":"(","replace":"target"}]"#.to_string().into(),
                "[]".to_string().into(),
            ),
            ("enabled", SeaValue::Int(Some(2)), SeaValue::Int(Some(1))),
            (
                "sub_account_enabled",
                "not-an-integer".to_string().into(),
                SeaValue::Int(Some(0)),
            ),
            (
                "model_limits_enabled",
                SeaValue::Int(Some(2)),
                SeaValue::Int(Some(0)),
            ),
            (
                "reasoning_envelope_enabled",
                SeaValue::Int(Some(2)),
                SeaValue::Int(Some(1)),
            ),
            (
                "request_capture_mode",
                "unsupported".to_string().into(),
                "off".to_string().into(),
            ),
            (
                "request_capture_retention",
                "3 days".to_string().into(),
                "24h".to_string().into(),
            ),
        ];

        for (column, invalid, valid) in api_key_cases {
            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE api_keys SET {column} = $1 WHERE id = $2"),
                    vec![invalid, api_key.id.clone().into()],
                ))
                .await
                .expect("corrupt API-key policy column");

            let error = store
                .validate_api_key(&token)
                .await
                .expect_err("corrupt API-key policy must fail validation");
            assert!(error.contains(column), "{column}: {error}");
            assert!(store.api_key_cache.get(&token).is_none());

            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE api_keys SET {column} = $1 WHERE id = $2"),
                    vec![valid, api_key.id.clone().into()],
                ))
                .await
                .expect("restore API-key policy column");
        }

        // users.group_id needs no corruption case here: it is NOT NULL at the
        // schema level and any stored text decodes as an opaque id.
        for (column, invalid, valid) in [(
            "enabled",
            SeaValue::Int(Some(2)),
            SeaValue::Int(Some(1)),
        )] {
            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE users SET {column} = $1 WHERE id = $2"),
                    vec![invalid, user.id.clone().into()],
                ))
                .await
                .expect("corrupt user policy column");

            let error = store
                .validate_api_key(&token)
                .await
                .expect_err("corrupt user policy must fail validation");
            assert!(error.contains(column), "{column}: {error}");
            assert!(store.api_key_cache.get(&token).is_none());

            db.write()
                .await
                .execute(db.stmt(
                    &format!("UPDATE users SET {column} = $1 WHERE id = $2"),
                    vec![valid, user.id.clone().into()],
                ))
                .await
                .expect("restore user policy column");
        }

        let last_used_at = db
            .read()
            .query_one(db.stmt(
                "SELECT last_used_at FROM api_keys WHERE id = $1",
                vec![api_key.id.into()],
            ))
            .await
            .expect("last-used query")
            .expect("key row exists")
            .try_get::<Option<String>>("", "last_used_at")
            .expect("last-used decodes");
        assert!(last_used_at.is_none());

        store
            .validate_api_key(&token)
            .await
            .expect("restored policy validates")
            .expect("restored key authenticates");
        assert!(store.api_key_cache.get(&token).is_some());
    }

    #[tokio::test]
    async fn delete_user_uses_reverse_invalidation_without_returning_key_ids() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("delete-cache", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let mut tokens = Vec::new();
        for name in ["first", "second", "third"] {
            let (_, token) = store
                .create_api_key(&user.id, name, None)
                .await
                .expect("key creates");
            store
                .validate_api_key(&token)
                .await
                .expect("key validates")
                .expect("key exists");
            tokens.push(token);
        }
        store
            .get_user_balance(&user.id)
            .await
            .expect("balance reads")
            .expect("balance exists");
        assert!(
            tokens
                .iter()
                .all(|token| store.api_key_cache.get(token).is_some())
        );
        assert!(store.balance_cache.get(&user.id).is_some());

        store.delete_user(&user.id).await.expect("user deletes");

        assert!(
            tokens
                .iter()
                .all(|token| store.api_key_cache.get(token).is_none())
        );
        assert!(store.balance_cache.get(&user.id).is_none());
        assert!(store.get_user_by_id(&user.id).await.unwrap().is_none());
        assert!(store.delete_user(&user.id).await.is_err());
    }

    #[tokio::test]
    async fn session_cleanup_is_indexed_set_delete_and_runs_at_store_startup() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let index = db
            .read()
            .query_one(db.stmt(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = $1",
                vec!["idx_sessions_expires_at".into()],
            ))
            .await
            .expect("index query succeeds");
        assert!(index.is_some());

        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("session-cleanup", "password", UserRole::User, None)
            .await
            .expect("user creates");
        store
            .create_session(&user.id, -1)
            .await
            .expect("expired session creates");
        let future = store
            .create_session(&user.id, 1)
            .await
            .expect("future session creates");

        let (second_broadcast, _) = tokio::sync::broadcast::channel(4);
        let restarted = UserStore::new(db.clone(), second_broadcast)
            .await
            .expect("restarted store creates");
        let remaining = db
            .read()
            .query_one(db.stmt("SELECT COUNT(*) AS count FROM sessions", vec![]))
            .await
            .expect("session count succeeds")
            .expect("count row exists");
        let remaining: i64 = remaining.try_get("", "count").expect("count decodes");
        assert_eq!(remaining, 1);
        assert!(
            restarted
                .get_session_by_token(&future.token)
                .await
                .expect("future session reads")
                .is_some()
        );

        db.write()
            .await
            .execute(db.stmt(
                "UPDATE sessions SET expires_at = $1 WHERE token = $2",
                vec![
                    (Utc::now() - chrono::Duration::seconds(1))
                        .to_rfc3339()
                        .into(),
                    future.token.into(),
                ],
            ))
            .await
            .expect("session expires");
        assert_eq!(
            restarted
                .cleanup_expired_sessions()
                .await
                .expect("cleanup succeeds"),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_registration_creates_exactly_one_first_super_admin() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for username in ["first-racer", "second-racer"] {
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .register_user_atomic(username, "password123", false)
                    .await
            }));
        }

        let mut users = Vec::new();
        let mut disabled = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(user) => users.push(user),
                Err(RegisterUserError::RegistrationDisabled) => disabled += 1,
                Err(error) => panic!("unexpected registration result: {error:?}"),
            }
        }
        assert_eq!(users.len(), 1);
        assert_eq!(disabled, 1);
        assert_eq!(users[0].role, UserRole::SuperAdmin);
        assert_eq!(store.user_count().await.unwrap(), 1);
    }

    fn limited_api_key_input(name: String) -> CreateApiKeyInput {
        CreateApiKeyInput {
            name,
            expires_in_days: None,
            sub_account_enabled: false,
            sub_account_balance_nano_usd: None,
            model_limits_enabled: false,
            model_limits: Vec::new(),
            ip_whitelist: Vec::new(),
            use_user_group: true,
            group_ids: Vec::new(),
            max_multiplier: None,
            transforms: Vec::new(),
            model_redirects: Vec::new(),
            reasoning_envelope_enabled: true,
            request_capture_mode: RequestCaptureMode::Off,
            request_capture_retention: RequestCaptureRetention::default(),
        }
    }

    #[tokio::test]
    async fn concurrent_api_key_creation_never_exceeds_user_limit() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("key-limit-user", "password123", UserRole::User, None)
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(6));
        let mut tasks = Vec::new();
        for index in 0..6 {
            let store = store.clone();
            let barrier = barrier.clone();
            let user_id = user.id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .create_api_key_extended_with_limit(
                        &user_id,
                        limited_api_key_input(format!("key-{index}")),
                        false,
                        2,
                    )
                    .await
            }));
        }

        let mut created = 0;
        let mut rejected = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => created += 1,
                Err(CreateApiKeyWithLimitError::LimitReached { limit: 2 }) => rejected += 1,
                Err(error) => panic!("unexpected key creation result: {error:?}"),
            }
        }
        assert_eq!(created, 2);
        assert_eq!(rejected, 4);
        assert_eq!(store.count_user_api_keys(&user.id).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn admin_user_update_rolls_back_ordinary_fields_when_ledger_insert_fails() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("atomic-before", "password123", UserRole::User, None)
            .await
            .unwrap();
        let session = store.create_session(&user.id, 7).await.unwrap();
        db.write()
            .await
            .execute(db.stmt(
                "CREATE TRIGGER fail_admin_adjustment
                 BEFORE INSERT ON billing_ledger
                 WHEN NEW.kind = 'admin_adjustment'
                 BEGIN SELECT RAISE(FAIL, 'ledger blocked'); END",
                vec![],
            ))
            .await
            .unwrap();

        let result = store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    username: Some("atomic-after".to_string()),
                    password: Some("new-password123".to_string()),
                    balance_nano_usd: Some("50".to_string()),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await;
        assert!(result.is_err());

        let unchanged = store.get_user_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(unchanged.username, "atomic-before");
        assert_eq!(unchanged.balance_nano_usd, "0");
        assert!(
            UserStore::verify_password_async("password123", &unchanged.password_hash)
                .await
                .unwrap()
        );
        assert!(
            store
                .get_session_by_token(&session.token)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn user_security_mutations_revoke_existing_sessions() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("session-revocation", "password123", UserRole::User, None)
            .await
            .unwrap();

        let password_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .update_user(
                &user.id,
                None,
                Some("password456"),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&password_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let role_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .update_user(
                &user.id,
                None,
                None,
                Some(UserRole::Admin),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&role_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let disabled_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .update_user(
                &user.id,
                None,
                None,
                None,
                Some(false),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&disabled_session.token)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn atomic_admin_security_mutations_revoke_existing_sessions() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("admin-revocation", "password123", UserRole::User, None)
            .await
            .unwrap();

        let password_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    password: Some("password456".to_string()),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&password_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let role_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    role: Some(UserRole::Admin),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&role_session.token)
                .await
                .unwrap()
                .is_none()
        );

        let disabled_session = store.create_session(&user.id, 7).await.unwrap();
        store
            .admin_update_user_atomic(
                &user.id,
                AdminUpdateUserInput {
                    enabled: Some(false),
                    ..AdminUpdateUserInput::default()
                },
                "admin-1",
            )
            .await
            .unwrap();
        assert!(
            store
                .get_session_by_token(&disabled_session.token)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn batch_delete_settles_multiple_keys_for_one_user() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db.clone(), log_broadcast)
            .await
            .expect("store creates");
        let user = store
            .create_user("batch-settlement", "password", UserRole::User, None)
            .await
            .expect("user creates");
        let (first, _) = store
            .create_api_key(&user.id, "first", None)
            .await
            .expect("first key creates");
        let (second, _) = store
            .create_api_key(&user.id, "second", None)
            .await
            .expect("second key creates");
        db.write()
            .await
            .execute(db.stmt(
                "UPDATE users SET balance_nano_usd = '100' WHERE id = $1",
                vec![user.id.clone().into()],
            ))
            .await
            .expect("user balance seeds");
        for (id, balance) in [(&first.id, "5"), (&second.id, "7")] {
            db.write()
                .await
                .execute(db.stmt(
                    "UPDATE api_keys
                     SET sub_account_enabled = 1, sub_account_balance_nano = $1
                     WHERE id = $2",
                    vec![balance.into(), id.as_str().into()],
                ))
                .await
                .expect("key balance seeds");
        }

        assert_eq!(
            store
                .batch_delete_api_keys(&[second.id.clone(), first.id.clone()])
                .await
                .expect("batch deletes"),
            2
        );
        let user_row = db
            .read()
            .query_one(db.stmt(
                "SELECT balance_nano_usd FROM users WHERE id = $1",
                vec![user.id.clone().into()],
            ))
            .await
            .expect("user query")
            .expect("user remains");
        assert_eq!(
            user_row
                .try_get::<String>("", "balance_nano_usd")
                .expect("balance decodes"),
            "112"
        );
        let ledger_rows = db
            .read()
            .query_all(db.stmt(
                "SELECT delta_nano_usd FROM billing_ledger
                 WHERE user_id = $1 AND kind = 'sub_account_delete_settlement'",
                vec![user.id.into()],
            ))
            .await
            .expect("ledger query");
        let mut deltas = ledger_rows
            .into_iter()
            .map(|row| {
                row.try_get::<String>("", "delta_nano_usd")
                    .expect("delta decodes")
            })
            .collect::<Vec<_>>();
        deltas.sort();
        assert_eq!(deltas, vec!["5".to_string(), "7".to_string()]);
    }

    #[test]
    fn ip_whitelist_accepts_and_canonicalizes_addresses_and_networks() {
        let values = canonicalize_ip_whitelist(&[
            " 2001:0db8::1 ".to_string(),
            "192.0.2.7".to_string(),
            "192.0.2.0/24".to_string(),
            "192.0.2.7".to_string(),
        ])
        .expect("valid whitelist");
        assert_eq!(
            values,
            vec![
                "192.0.2.0/24".to_string(),
                "192.0.2.7".to_string(),
                "2001:db8::1".to_string(),
            ]
        );
        assert!(canonicalize_ip_whitelist(&["not-an-ip".to_string()]).is_err());
    }

    #[test]
    fn sanitize_api_key_transforms_drops_disallowed_rules() {
        let transforms = vec![TransformRuleConfig {
            transform: "field_set".to_string(),
            enabled: true,
            models: Some(vec!["gpt-5.4-fast".to_string()]),
            phase: Phase::Request,
            config: json!({
                "path": "service_tier",
                "value": "priority"
            }),
        }];

        let sanitized = sanitize_api_key_transforms(transforms, false, &Default::default());
        assert!(sanitized.is_empty());
    }

    #[test]
    fn validate_api_key_transforms_allows_image_compression() {
        let transforms = vec![TransformRuleConfig {
            transform: "image_compress_input".to_string(),
            enabled: true,
            models: None,
            phase: Phase::Request,
            config: json!({
                "max_edge_px": 1024,
                "jpeg_quality": 80,
                "skip_if_smaller": true
            }),
        }];

        assert!(validate_api_key_transforms(&transforms, false, &Default::default()).is_ok());
    }

    #[test]
    fn validate_api_key_transforms_allows_openai_tool_cache_breakpoints() {
        let transforms = vec![TransformRuleConfig {
            transform: "cache_openai_tool_use".to_string(),
            enabled: true,
            models: Some(vec!["gpt-5.6*".to_string()]),
            phase: Phase::Request,
            config: json!({}),
        }];

        assert!(validate_api_key_transforms(&transforms, false, &Default::default()).is_ok());
    }

    #[test]
    fn sanitize_api_key_transforms_canonicalizes_allowed_aliases() {
        let transforms = vec![TransformRuleConfig {
            transform: "remove_anthropic_billing_header".to_string(),
            enabled: true,
            models: None,
            phase: Phase::Request,
            config: json!({}),
        }];

        let sanitized = sanitize_api_key_transforms(transforms, false, &Default::default());

        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].transform, "prompt_strip_anthropic_billing_header");
    }

    #[test]
    fn validate_api_key_transforms_allows_new_response_transforms() {
        let transforms = vec![
            TransformRuleConfig {
                transform: "reasoning_content_to_summary".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "reasoning_strip_encrypted".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "image_markdown_to_output".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "reasoning_inject_content_field".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "reasoning_summary_to_raw_cot".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "image_output_to_markdown".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({}),
            },
            TransformRuleConfig {
                transform: "image_compress_output".to_string(),
                enabled: true,
                models: None,
                phase: Phase::Response,
                config: json!({
                    "max_edge_px": 1024,
                    "jpeg_quality": 80,
                    "skip_if_smaller": true
                }),
            },
        ];

        assert!(validate_api_key_transforms(&transforms, false, &Default::default()).is_ok());
    }

    /// CJS-AKV-2/CJS-AKV-3: `js:` rules pass for non-admins exactly when the
    /// enabled snapshot entry is user-visible, api_key-scoped, and declares
    /// the rule phase.
    #[test]
    fn api_key_transforms_gate_custom_js_rules_by_snapshot() {
        use crate::custom_transforms::{
            CustomTransformEntry, CustomTransformSnapshot, CustomTransformVisibility,
        };
        use crate::transforms::TransformScope;
        use std::sync::Arc;

        let entry = |id: &str,
                     visibility: CustomTransformVisibility,
                     scopes: Vec<TransformScope>,
                     phases: Vec<Phase>| {
            (
                id.to_string(),
                Arc::new(CustomTransformEntry {
                    id: id.to_string(),
                    name: "n".to_string(),
                    description: "d".to_string(),
                    author: "a".to_string(),
                    source: "function transform(ctx) {}".to_string(),
                    visibility,
                    phases,
                    scopes,
                    config_schema: None,
                }),
            )
        };
        let snapshot = CustomTransformSnapshot::from_entries(
            [
                entry(
                    "js:allowed",
                    CustomTransformVisibility::User,
                    vec![TransformScope::ApiKey],
                    vec![Phase::Request],
                ),
                entry(
                    "js:admin-only",
                    CustomTransformVisibility::Admin,
                    vec![TransformScope::ApiKey],
                    vec![Phase::Request],
                ),
                entry(
                    "js:wrong-scope",
                    CustomTransformVisibility::User,
                    vec![TransformScope::Provider],
                    vec![Phase::Request],
                ),
            ]
            .into_iter()
            .collect(),
        );
        let rule = |id: &str, phase: Phase| TransformRuleConfig {
            transform: id.to_string(),
            enabled: true,
            models: None,
            phase,
            config: json!({}),
        };

        assert!(
            validate_api_key_transforms(&[rule("js:allowed", Phase::Request)], false, &snapshot)
                .is_ok()
        );
        for (id, phase) in [
            ("js:admin-only", Phase::Request),
            ("js:wrong-scope", Phase::Request),
            ("js:allowed", Phase::Response),
            ("js:missing", Phase::Request),
        ] {
            assert!(
                validate_api_key_transforms(&[rule(id, phase)], false, &snapshot).is_err(),
                "rule {id} in phase {phase:?} must be rejected"
            );
        }
        // Admin bypass keeps every rule.
        assert!(
            validate_api_key_transforms(
                &[rule("js:admin-only", Phase::Request)],
                true,
                &snapshot
            )
            .is_ok()
        );

        let sanitized = sanitize_api_key_transforms(
            vec![
                rule("js:allowed", Phase::Request),
                rule("js:admin-only", Phase::Request),
            ],
            false,
            &snapshot,
        );
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].transform, "js:allowed");
    }

    #[test]
    fn sanitize_api_key_transforms_preserves_disallowed_rules_for_admin() {
        let transforms = vec![TransformRuleConfig {
            transform: "field_set".to_string(),
            enabled: true,
            models: Some(vec!["gpt-5.4-fast".to_string()]),
            phase: Phase::Request,
            config: json!({
                "path": "service_tier",
                "value": "priority"
            }),
        }];

        let sanitized = sanitize_api_key_transforms(transforms.clone(), true, &Default::default());
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].transform, transforms[0].transform);
        assert_eq!(sanitized[0].enabled, transforms[0].enabled);
        assert_eq!(sanitized[0].models, transforms[0].models);
        assert_eq!(sanitized[0].phase as u8, transforms[0].phase as u8);
        assert_eq!(sanitized[0].config, transforms[0].config);
    }

    #[test]
    fn group_ids_json_compatibility_does_not_accept_corruption() {
        for raw in [None, Some(""), Some("   "), Some("null"), Some("[]")] {
            assert!(
                parse_group_ids_json(raw, "group_ids")
                    .expect("compatibility value parses")
                    .is_empty()
            );
        }
        for raw in ["not-json", "{}", r#"["group", 1]"#] {
            assert!(parse_group_ids_json(Some(raw), "group_ids").is_err());
        }
        // Ids are opaque UUID strings: trim + dedupe, but preserve order and case.
        assert_eq!(
            parse_group_ids_json(Some(r#"[" g-b ","g-a","g-b",""]"#), "group_ids")
                .expect("valid group ids parse"),
            vec!["g-b".to_string(), "g-a".to_string()]
        );
        assert_eq!(
            serialize_group_ids_json(&[
                " g-b ".to_string(),
                "g-a".to_string(),
                "g-b".to_string(),
            ])
            .expect("serialize group ids"),
            r#"["g-b","g-a"]"#
        );
    }

    #[tokio::test]
    async fn api_key_group_selection_rejects_unknown_and_non_selectable_groups() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let (log_broadcast, _) = tokio::sync::broadcast::channel(4);
        let store = UserStore::new(db, log_broadcast)
            .await
            .expect("store creates");
        let default_id = store.default_group_id().await.expect("default exists");

        let hidden = store
            .create_group(CreateGroupInput {
                name: "hidden".to_string(),
                description: String::new(),
                user_selectable: false,
                sort_order: 5,
            })
            .await
            .expect("hidden group created");
        let open = store
            .create_group(CreateGroupInput {
                name: "open".to_string(),
                description: String::new(),
                user_selectable: true,
                sort_order: 6,
            })
            .await
            .expect("open group created");

        // Admin may select any registered group.
        store
            .validate_api_key_group_selection(&default_id, &[hidden.id.clone()], true)
            .await
            .expect("admin selects non-selectable group");
        // Non-admin may select user_selectable groups and their own group.
        store
            .validate_api_key_group_selection(&default_id, &[open.id.clone()], false)
            .await
            .expect("non-admin selects user_selectable group");
        store
            .validate_api_key_group_selection(&hidden.id, &[hidden.id.clone()], false)
            .await
            .expect("non-admin keeps own group");
        // Non-admin may not select other non-selectable groups.
        let err = store
            .validate_api_key_group_selection(&default_id, &[hidden.id.clone()], false)
            .await
            .expect_err("non-selectable group rejected");
        assert!(err.contains("not selectable"));
        // Unknown ids are always rejected.
        let err = store
            .validate_api_key_group_selection(&default_id, &["missing".to_string()], false)
            .await
            .expect_err("unknown group rejected");
        assert!(err.contains("unknown group id"));
    }
