    use super::*;
    use super::decode::*;
    use super::health::*;
    use super::probe::{build_probe_request, extract_probe_usage};
    use super::validate::validate_api_type_overrides;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use serde_json::json;
    use crate::db::DbPool;
    use crate::migration::Migrator;
    use sea_orm::ConnectionTrait;
    use sea_orm_migration::MigratorTrait;

    #[test]
    fn entry_limit_parser_requires_a_positive_integer() {
        assert_eq!(parse_positive_entry_limit(Some("17"), 9), 17);
        assert_eq!(parse_positive_entry_limit(Some(" 3 "), 9), 3);
        assert_eq!(parse_positive_entry_limit(Some("0"), 9), 9);
        assert_eq!(parse_positive_entry_limit(Some("-1"), 9), 9);
        assert_eq!(parse_positive_entry_limit(Some("invalid"), 9), 9);
        assert_eq!(parse_positive_entry_limit(None, 9), 9);
        assert_eq!(parse_provider_reorder_limit(Some("17")), 17);
        assert_eq!(parse_provider_reorder_limit(Some("200")), 199);
        assert_eq!(parse_provider_reorder_limit(Some("0")), 199);
        assert_eq!(parse_provider_reorder_limit(Some("invalid")), 199);
        assert_eq!(
            parse_channel_affinity_cleanup_interval(Some("17")),
            Duration::from_secs(17)
        );
        for raw in ["", "0", "-1", "invalid"] {
            assert_eq!(
                parse_channel_affinity_cleanup_interval(Some(raw)),
                Duration::from_secs(DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS)
            );
        }
        assert_eq!(
            parse_channel_affinity_cleanup_interval(None),
            Duration::from_secs(DEFAULT_CHANNEL_AFFINITY_CLEANUP_INTERVAL_SECONDS)
        );
    }

    #[test]
    fn passive_failure_threshold_is_positive_and_capped() {
        assert_eq!(effective_passive_failure_threshold_with_limit(0, 1024), 1);
        assert_eq!(effective_passive_failure_threshold_with_limit(3, 1024), 3);
        assert_eq!(
            effective_passive_failure_threshold_with_limit(2048, 1024),
            1024
        );
        assert_eq!(effective_passive_failure_threshold_with_limit(3, 0), 1);
    }

    #[test]
    fn persisted_routing_booleans_accept_only_zero_and_one() {
        assert!(!decode_database_bool("provider", "p1", "enabled", 0).unwrap());
        assert!(decode_database_bool("channel", "c1", "enabled", 1).unwrap());
        assert!(decode_database_bool("provider", "p1", "enabled", -1).is_err());
        assert!(decode_database_bool("channel", "c1", "enabled", 2).is_err());
    }

    #[test]
    fn health_capacity_fails_closed_without_scanning_or_eviction() {
        let mut health = HashMap::from([
            (
                "unhealthy".to_string(),
                ChannelHealthState {
                    healthy: false,
                    ..ChannelHealthState::new()
                },
            ),
            ("healthy".to_string(), ChannelHealthState::new()),
        ]);
        assert!(!prepare_channel_health_insert_with_limit(
            &mut health,
            "new",
            2
        ));
        assert!(health.contains_key("unhealthy"));
        assert!(health.contains_key("healthy"));
        assert!(missing_channel_health_is_saturated_with_limit(
            &health, "new", 2
        ));
        assert_eq!(health.len(), 2);
    }

    #[tokio::test]
    async fn transform_id_migration_crosses_keyset_batch_boundary_and_marks_completion() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let legacy_transforms = json!([{
            "transform": "openai_prompt_cache",
            "phase": "request"
        }])
        .to_string();
        let now = Utc::now().to_rfc3339();
        let row_count = TRANSFORM_MIGRATION_BATCH_SIZE + 3;
        let mut values = Vec::with_capacity(row_count * 4);
        let mut rows = Vec::with_capacity(row_count);
        for index in 0..row_count {
            let start = values.len() + 1;
            values.extend([
                format!("provider-{index:04}").into(),
                format!("provider {index}").into(),
                legacy_transforms.clone().into(),
                now.clone().into(),
            ]);
            rows.push(format!(
                "(${start}, ${}, ${}, ${}, ${})",
                start + 1,
                start + 2,
                start + 3,
                start + 3
            ));
        }
        db.write()
            .await
            .execute(db.stmt(
                &format!(
                    "INSERT INTO monoize_providers
                     (id, name, transforms, created_at, updated_at) VALUES {}",
                    rows.join(", ")
                ),
                values,
            ))
            .await
            .expect("legacy providers insert");

        MonoizeRoutingStore::new(db.clone())
            .await
            .expect("store migrates transforms");

        let transformed = db
            .read()
            .query_all(db.stmt(
                "SELECT transforms FROM monoize_providers ORDER BY id ASC",
                vec![],
            ))
            .await
            .expect("transforms load");
        assert_eq!(transformed.len(), row_count);
        for row in transformed {
            let raw: String = row.try_get("", "transforms").expect("transforms decode");
            let rules: Vec<TransformRuleConfig> =
                serde_json::from_str(&raw).expect("transforms parse");
            assert_eq!(rules[0].transform, "cache_openai_prompt");
        }
        let marker = db
            .read()
            .query_one(db.stmt(
                "SELECT value FROM system_settings WHERE key = $1",
                vec![TRANSFORM_MIGRATION_MARKER.into()],
            ))
            .await
            .expect("marker loads")
            .expect("marker exists")
            .try_get::<String>("", "value")
            .expect("marker decodes");
        assert_eq!(marker, "complete");
    }

    #[tokio::test]
    async fn routing_reads_fail_closed_on_non_boolean_integer() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let store = MonoizeRoutingStore::new(db.clone())
            .await
            .expect("store creates");
        let provider = store
            .create_provider(
                serde_json::from_value(json!({
                    "name": "decode contract",
                    "channels": [{
                        "name": "channel",
                        "provider_type": "responses",
                        "base_url": "https://example.com",
                        "api_key": "secret",
                        "models": { "model-a": { "redirect": null, "multiplier": "1" } }
                    }]
                }))
                .expect("provider input parses"),
            )
            .await
            .expect("provider creates");

        db.write()
            .await
            .execute(db.stmt(
                "UPDATE monoize_providers SET enabled = 2 WHERE id = $1",
                vec![provider.id.clone().into()],
            ))
            .await
            .expect("provider boolean becomes malformed");
        assert!(store.get_provider(&provider.id).await.is_err());
    }

    #[tokio::test]
    async fn available_model_names_are_sorted_and_exclude_ineligible_channels() {
        let db = DbPool::connect("sqlite::memory:")
            .await
            .expect("db connects");
        {
            let write = db.write().await;
            Migrator::up(&*write, None).await.expect("migrates");
        }
        let store = MonoizeRoutingStore::new(db.clone())
            .await
            .expect("store creates");
        store
            .reorder_providers(ReorderProvidersInput {
                provider_ids: Vec::new(),
            })
            .await
            .expect("empty provider reorder succeeds");
        let input: CreateMonoizeProviderInput = serde_json::from_value(json!({
            "name": "visible models",
            "strip_cross_protocol_nested_extra": false,
            "channels": [
                {
                    "name": "active",
                    "provider_type": "responses",
                    "base_url": "https://example.com",
                    "api_key": "secret",
                    "models": {
                        "model-z": { "redirect": null, "multiplier": "1" },
                        "model-a": { "redirect": null, "multiplier": "1" }
                    }
                },
                {
                    "name": "disabled",
                    "provider_type": "responses",
                    "base_url": "https://example.com",
                    "api_key": "secret",
                    "enabled": false,
                    "models": { "model-hidden": { "redirect": null, "multiplier": "1" } }
                },
                {
                    "name": "zero weight",
                    "provider_type": "responses",
                    "base_url": "https://example.com",
                    "api_key": "secret",
                    "weight": 0,
                    "models": { "model-zero": { "redirect": null, "multiplier": "1" } }
                }
            ]
        }))
        .expect("provider input parses");
        let created = store
            .create_provider(input)
            .await
            .expect("provider creates");

        assert_eq!(
            store
                .list_available_model_names()
                .await
                .expect("names list"),
            vec!["model-a".to_string(), "model-z".to_string()]
        );
        assert_eq!(
            store
                .available_model_names(&[
                    "model-hidden".to_string(),
                    "model-zero".to_string(),
                    "model-z".to_string(),
                ])
                .await
                .expect("candidate availability loads"),
            HashSet::from(["model-z".to_string()])
        );
        let listed = store.list_providers().await.expect("providers list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].strip_cross_protocol_nested_extra, Some(false));
        assert_eq!(listed[0].channels.len(), 3);
        assert_eq!(listed[0].channels[0].models.len(), 2);
        let fetched = store
            .get_provider(&created.id)
            .await
            .expect("provider loads")
            .expect("provider exists");
        assert_eq!(fetched.channels.len(), 3);
        assert_eq!(fetched.channels[0].models.len(), 2);
        assert_eq!(fetched.strip_cross_protocol_nested_extra, Some(false));
        assert_eq!(
            store
                .list_providers_for_model("model-a")
                .await
                .expect("model providers list")[0]
                .strip_cross_protocol_nested_extra,
            Some(false)
        );
        assert!(
            store
                .list_providers_for_model("model-hidden")
                .await
                .expect("disabled channel lookup")
                .is_empty()
        );
        assert!(
            store
                .list_providers_for_model("model-zero")
                .await
                .expect("zero-weight channel lookup")
                .is_empty()
        );
        let active_probe_candidates = store
            .list_active_probe_candidates()
            .await
            .expect("active probe candidates list");
        assert_eq!(active_probe_candidates.len(), 1);
        assert_eq!(
            active_probe_candidates[0].strip_cross_protocol_nested_extra,
            Some(false)
        );
        assert_eq!(active_probe_candidates[0].channels.len(), 1);
        assert_eq!(active_probe_candidates[0].channels[0].name, "active");

        let second_input: CreateMonoizeProviderInput = serde_json::from_value(json!({
            "name": "second",
            "channels": [{
                "name": "second channel",
                "provider_type": "responses",
                "base_url": "https://example.com",
                "api_key": "secret",
                "models": { "model-second": { "redirect": null, "multiplier": "1" } }
            }]
        }))
        .expect("second provider input parses");
        let second = store
            .create_provider(second_input)
            .await
            .expect("second provider creates");
        assert_eq!(created.priority, 0);
        assert_eq!(second.priority, 1);
        store
            .reorder_providers(ReorderProvidersInput {
                provider_ids: vec![second.id.clone(), created.id.clone()],
            })
            .await
            .expect("providers reorder");
        assert_eq!(
            store
                .list_providers()
                .await
                .expect("reordered providers list")
                .into_iter()
                .map(|provider| provider.id)
                .collect::<Vec<_>>(),
            vec![second.id.clone(), created.id.clone()]
        );

        let disabled_provider: CreateMonoizeProviderInput = serde_json::from_value(json!({
            "name": "disabled provider",
            "enabled": false,
            "channels": [{
                "name": "active channel",
                "provider_type": "responses",
                "base_url": "https://example.com",
                "api_key": "secret",
                "models": {
                    "model-disabled-provider": { "redirect": null, "multiplier": "1" }
                }
            }]
        }))
        .expect("disabled provider input parses");
        store
            .create_provider(disabled_provider)
            .await
            .expect("disabled provider creates");
        assert!(
            store
                .list_providers_for_model("model-disabled-provider")
                .await
                .expect("disabled provider lookup")
                .is_empty()
        );
        assert!(
            store
                .list_active_probe_candidates()
                .await
                .expect("active probe candidates reload")
                .iter()
                .all(|provider| provider.enabled
                    && provider
                        .channels
                        .iter()
                        .all(|channel| channel.enabled && channel.weight > 0))
        );

        db.write()
            .await
            .execute(db.stmt(
                "UPDATE monoize_providers SET extra_fields_whitelist = $1 WHERE id = $2",
                vec!["not-json".into(), created.id.clone().into()],
            ))
            .await
            .expect("corrupt whitelist writes");
        assert!(
            store
                .get_provider(&created.id)
                .await
                .expect_err("invalid whitelist must fail provider decoding")
                .contains("invalid extra_fields_whitelist JSON")
        );
    }

    #[test]
    fn probe_request_plan_routes_each_api_type() {
        let (resp_url, resp_body, resp_headers, resp_google_auth) = build_probe_request(
            "https://up.example",
            "gpt-5-mini",
            MonoizeProviderType::Responses,
            false,
        );
        assert_eq!(resp_url, "https://up.example/v1/responses");
        assert!(!resp_google_auth);
        assert!(resp_headers.is_empty());
        assert_eq!(resp_body["max_output_tokens"].as_u64(), Some(16));
        assert_eq!(resp_body["stream"].as_bool(), Some(false));
        assert!(resp_body.get("input").is_some());

        let (chat_url, chat_body, chat_headers, chat_google_auth) = build_probe_request(
            "https://up.example",
            "gpt-5-mini",
            MonoizeProviderType::ChatCompletion,
            false,
        );
        assert_eq!(chat_url, "https://up.example/v1/chat/completions");
        assert!(!chat_google_auth);
        assert!(chat_headers.is_empty());
        assert_eq!(chat_body["max_tokens"].as_u64(), Some(16));
        assert_eq!(chat_body["stream"].as_bool(), Some(false));
        assert!(chat_body.get("messages").is_some());

        let (msg_url, msg_body, msg_headers, msg_google_auth) = build_probe_request(
            "https://up.example",
            "claude-3-7-sonnet",
            MonoizeProviderType::Messages,
            false,
        );
        assert_eq!(msg_url, "https://up.example/v1/messages");
        assert!(!msg_google_auth);
        assert_eq!(msg_headers, &[("anthropic-version", "2023-06-01")]);
        assert_eq!(msg_body["max_tokens"].as_u64(), Some(16));
        assert_eq!(msg_body["stream"].as_bool(), Some(false));
        assert!(msg_body.get("messages").is_some());

        let (gem_url, gem_body, gem_headers, gem_google_auth) = build_probe_request(
            "https://up.example",
            "gemini-2.5-flash",
            MonoizeProviderType::Gemini,
            false,
        );
        assert_eq!(
            gem_url,
            "https://up.example/v1beta/models/gemini-2.5-flash:generateContent"
        );
        assert!(gem_google_auth);
        assert!(gem_headers.is_empty());
        assert_eq!(
            gem_body["generationConfig"]["maxOutputTokens"].as_u64(),
            Some(16)
        );
        assert!(gem_body.get("contents").is_some());

        let (stream_url, stream_body, _, _) = build_probe_request(
            "https://up.example",
            "gpt-5-mini",
            MonoizeProviderType::Responses,
            true,
        );
        assert_eq!(stream_url, "https://up.example/v1/responses");
        assert_eq!(stream_body["stream"].as_bool(), Some(true));

        let (gem_stream_url, _, _, _) = build_probe_request(
            "https://up.example",
            "gemini-2.5-flash",
            MonoizeProviderType::Gemini,
            true,
        );
        assert_eq!(
            gem_stream_url,
            "https://up.example/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );

        let (img_url, img_body, img_headers, img_google_auth) = build_probe_request(
            "https://up.example",
            "gpt-image-1",
            MonoizeProviderType::OpenaiImage,
            false,
        );
        assert_eq!(img_url, "https://up.example/v1/images/generations");
        assert!(!img_google_auth);
        assert!(img_headers.is_empty());
        assert_eq!(img_body["model"].as_str(), Some("gpt-image-1"));
        assert_eq!(img_body["prompt"].as_str(), Some("test"));
        assert_eq!(img_body["size"].as_str(), Some("1024x1024"));
        assert_eq!(img_body["n"].as_u64(), Some(1));
    }

    #[test]
    fn format_probe_http_error_includes_status_reason_and_body() {
        assert_eq!(
            format_probe_http_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, ""),
            "upstream returned 500 Internal Server Error"
        );
        assert_eq!(
            format_probe_http_error(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "upstream requests error."
            ),
            "upstream returned 503 Service Unavailable: upstream requests error."
        );
    }

    #[test]
    fn extract_probe_usage_supports_gemini_usage_metadata() {
        let usage = extract_probe_usage(&json!({
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 8
            }
        }));
        assert_eq!(
            usage,
            Some(json!({"prompt_tokens": 12, "completion_tokens": 8}))
        );
    }

    #[test]
    fn validate_api_type_overrides_rejects_empty_pattern() {
        let err = validate_api_type_overrides(&[ApiTypeOverride {
            pattern: "   ".to_string(),
            api_type: MonoizeProviderType::ChatCompletion,
        }])
        .expect_err("expected invalid empty override pattern");
        assert!(err.contains("api_type_overrides[0].pattern must not be empty"));
    }

    #[test]
    fn decode_provider_group_ids_json_is_compatible_only_for_absent_and_empty_values() {
        assert!(
            decode_provider_group_ids_json("provider-a", None)
                .unwrap()
                .is_empty()
        );
        assert!(
            decode_provider_group_ids_json("provider-a", Some(String::new()))
                .unwrap()
                .is_empty()
        );
        assert!(
            decode_provider_group_ids_json("provider-a", Some("not-json".to_string())).is_err()
        );
        assert!(decode_provider_group_ids_json("provider-a", Some("[1]".to_string())).is_err());
        // Ids are opaque: order and casing must survive, duplicates and empties drop (GR-C1).
        assert_eq!(
            decode_provider_group_ids_json(
                "provider-a",
                Some(r#"[" g-B ","g-a","g-a",""]"#.to_string())
            )
            .unwrap(),
            vec!["g-B".to_string(), "g-a".to_string()]
        );
    }

    #[test]
    fn extra_headers_validation_accepts_valid_and_rejects_invalid() {
        let ok = BTreeMap::from([("x-session-affinity".to_string(), "ses_001".to_string())]);
        assert!(validate_channel_extra_headers("ch", &ok).is_ok());

        for (name, value) in [("Authorization", "x"), ("CONTENT-TYPE", "application/json")] {
            let reserved = BTreeMap::from([(name.to_string(), value.to_string())]);
            assert!(
                validate_channel_extra_headers("ch", &reserved).is_err(),
                "reserved header {name} must be rejected"
            );
        }

        let dup = BTreeMap::from([
            ("X-Test".to_string(), "a".to_string()),
            ("x-test".to_string(), "b".to_string()),
        ]);
        assert!(validate_channel_extra_headers("ch", &dup).is_err());

        let crlf = BTreeMap::from([("X-Ok".to_string(), "a\r\nb".to_string())]);
        assert!(validate_channel_extra_headers("ch", &crlf).is_err());

        let invalid_token = BTreeMap::from([("X Bad Header".to_string(), "v".to_string())]);
        assert!(validate_channel_extra_headers("ch", &invalid_token).is_err());

        let empty_key = BTreeMap::from([("   ".to_string(), "v".to_string())]);
        assert!(validate_channel_extra_headers("ch", &empty_key).is_err());

        let too_many: BTreeMap<String, String> = (0..EXTRA_HEADERS_MAX_ENTRIES + 1)
            .map(|index| (format!("X-H{index}"), "v".to_string()))
            .collect();
        assert!(validate_channel_extra_headers("ch", &too_many).is_err());
    }

    #[test]
    fn extra_headers_normalization_trims_keys_and_sorts_json() {
        let raw = BTreeMap::from([
            ("  Z-Last  ".to_string(), "2".to_string()),
            ("A-First".to_string(), "1".to_string()),
        ]);
        assert_eq!(
            normalized_extra_headers_json(Some(&raw)).unwrap(),
            r#"{"A-First":"1","Z-Last":"2"}"#
        );
        assert!(normalized_extra_headers_json(None).is_none());
        assert!(normalized_extra_headers_json(Some(&BTreeMap::new())).is_none());
    }

    #[test]
    fn extra_headers_decode_roundtrips_and_rejects_garbage() {
        assert!(decode_extra_headers(None).unwrap().is_none());
        assert!(
            decode_extra_headers(Some("  ".to_string()))
                .unwrap()
                .is_none()
        );
        let decoded = decode_extra_headers(Some(r#"{"X-A":"1"}"#.to_string()));
        assert!(decoded.is_ok());
        assert!(decode_extra_headers(Some("not-json".to_string())).is_err());

        let canonical = normalized_extra_headers_json(Some(&BTreeMap::from([(
            "X-Session-Affinity".to_string(),
            "ses_9".to_string(),
        )])))
        .unwrap();
        let round = decode_extra_headers(Some(canonical)).unwrap().unwrap();
        assert_eq!(
            round.get("X-Session-Affinity").map(String::as_str),
            Some("ses_9")
        );
    }
