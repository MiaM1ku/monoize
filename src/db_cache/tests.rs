    use super::*;
    use super::request_log::{
        REQUEST_LOG_INSERT_COLUMNS, RequestLogReservationInner, SpoolFileRef,
        atomic_saturating_sub,
    };
    use crate::users::{
        ApiKey, InsertRequestLog, RequestCaptureMode, RequestLogNameSnapshots, User, UserBalance,
        UserRole,
    };
    use chrono::Utc;
    use dashmap::DashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    fn spool_request_log(id: &str) -> SpoolRequestLog {
        SpoolRequestLog {
            id: id.to_string(),
            request_id: Some(format!("request-{id}")),
            user_id: "user-1".to_string(),
            api_key_id: Some("key-1".to_string()),
            model: "model-1".to_string(),
            provider_id: Some("provider-1".to_string()),
            upstream_model: Some("upstream-1".to_string()),
            channel_id: Some("channel-1".to_string()),
            is_stream: true,
            input_tokens: Some(1),
            output_tokens: Some(2),
            cache_read_tokens: Some(3),
            cache_creation_tokens: Some(4),
            tool_prompt_tokens: Some(5),
            reasoning_tokens: Some(6),
            accepted_prediction_tokens: Some(7),
            rejected_prediction_tokens: Some(8),
            provider_multiplier: Some("1".to_string()),
            charge_nano_usd: Some("9".to_string()),
            status: "success".to_string(),
            usage_breakdown_json: Some(serde_json::json!({"input": 1})),
            billing_breakdown_json: Some(serde_json::json!({"charge": "9"})),
            error_code: None,
            error_message: None,
            error_http_status: None,
            duration_ms: Some(10),
            ttfb_ms: Some(11),
            request_ip: Some("192.0.2.1".to_string()),
            reasoning_effort: Some("high".to_string()),
            tried_providers_json: Some(serde_json::json!(["provider-1"])),
            request_kind: Some("responses".to_string()),
            effective_provider_type: Some("responses".to_string()),
            affinity_hit: Some(true),
            affinity_key_hash: Some("hash".to_string()),
            affinity_target: Some("target".to_string()),
            session_affinity_value: Some("ses-1".to_string()),
            created_at: "2026-08-09T00:00:00+00:00".to_string(),
            created_at_unix_ms: 1_786_233_600_000,
        }
    }

    fn terminal_request_log(request_id: &str) -> InsertRequestLog {
        InsertRequestLog {
            request_id: Some(request_id.to_string()),
            user_id: "11111111-1111-1111-1111-111111111111".to_string(),
            api_key_id: Some("22222222-2222-2222-2222-222222222222".to_string()),
            model: "model-1".to_string(),
            provider_id: Some("provider-1".to_string()),
            upstream_model: Some("upstream-1".to_string()),
            channel_id: Some("channel-1".to_string()),
            names: RequestLogNameSnapshots::default(),
            is_stream: true,
            input_tokens: Some(1),
            output_tokens: Some(2),
            cache_read_tokens: None,
            cache_creation_tokens: None,
            tool_prompt_tokens: None,
            reasoning_tokens: None,
            accepted_prediction_tokens: None,
            rejected_prediction_tokens: None,
            provider_multiplier: None,
            charge_nano_usd: Some(3),
            status: "success".to_string(),
            usage_breakdown_json: None,
            billing_breakdown_json: None,
            error_code: None,
            error_message: None,
            error_http_status: None,
            duration_ms: Some(4),
            ttfb_ms: Some(5),
            request_ip: Some("192.0.2.1".to_string()),
            reasoning_effort: None,
            tried_providers_json: None,
            request_kind: Some("responses".to_string()),
            effective_provider_type: Some("responses".to_string()),
            affinity_hit: None,
            affinity_key_hash: None,
            affinity_target: None,
            session_affinity_value: None,
            created_at: Utc::now(),
        }
    }

    fn fallback_request_log(request_id: &str) -> InsertRequestLog {
        let mut log = terminal_request_log(request_id);
        log.status = "error".to_string();
        log.charge_nano_usd = None;
        log.error_code = Some("request_finalization_aborted".to_string());
        log.error_message = Some("request ended before terminal log persistence".to_string());
        log.error_http_status = Some(500);
        log
    }

    async fn arm_terminal(
        batcher: &RequestLogBatcher,
        reservation: &RequestLogReservation,
        request_id: &str,
    ) {
        batcher
            .arm_reserved(fallback_request_log(request_id), reservation)
            .await
            .expect("fallback arms");
    }

    fn cached_user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: format!("user-{id}"),
            password_hash: String::new(),
            role: UserRole::User,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
            enabled: true,
            balance_nano_usd: "0".to_string(),
            balance_unlimited: false,
            email: None,
            group_id: String::new(),
            billing_plan_id: None,
            next_grant_at: None,
        }
    }

    fn cached_api_key(id: &str, user_id: &str, token: &str) -> ApiKey {
        ApiKey {
            id: id.to_string(),
            user_id: user_id.to_string(),
            name: id.to_string(),
            key_prefix: token.chars().take(12).collect(),
            key: token.to_string(),
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            enabled: true,
            sub_account_enabled: false,
            sub_account_balance_nano: "0".to_string(),
            model_limits_enabled: false,
            model_limits: Vec::new(),
            ip_whitelist: Vec::new(),
            use_user_group: true,
            group_ids: Vec::new(),
            max_multiplier: None,
            transforms: Vec::new(),
            model_redirects: Vec::new(),
            compiled_model_redirects: Vec::new(),
            reasoning_envelope_enabled: true,
            request_capture_mode: RequestCaptureMode::Off,
            request_capture_retention: crate::users::RequestCaptureRetention::default(),
        }
    }

    #[test]
    fn last_used_buffer_is_bounded_but_updates_existing_key() {
        let batcher = LastUsedBatcher::with_capacity(1);
        let first = Utc::now();
        let later = first + chrono::Duration::seconds(1);
        batcher.record("key-1".to_string(), first);
        batcher.record("key-2".to_string(), later);
        batcher.record("key-1".to_string(), later);
        assert_eq!(batcher.buffer.len(), 1);
        assert_eq!(*batcher.buffer.get("key-1").unwrap(), later);
    }

    #[test]
    fn last_used_bulk_update_uses_one_statement_for_chunk() {
        let entries = vec![
            ("key-1".to_string(), Utc::now()),
            ("key-2".to_string(), Utc::now()),
        ];
        let (sql, values) = last_used_bulk_update(&entries);
        assert!(sql.contains("WHEN id = $1 THEN $2"));
        assert!(sql.contains("WHEN id = $3 THEN $4"));
        assert!(sql.ends_with("WHERE id IN ($1, $3)"));
        assert_eq!(values.len(), 4);
    }

    #[test]
    fn request_log_multi_row_insert_uses_contiguous_bind_slots() {
        let logs = [spool_request_log("1"), spool_request_log("2")];
        let (sql, values) = request_log_insert_chunk(logs.iter());
        let bind_slots = sql
            .split('$')
            .skip(1)
            .map(|tail| {
                tail.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse::<usize>()
                    .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            bind_slots,
            (1..=2 * REQUEST_LOG_INSERT_COLUMNS).collect::<Vec<_>>()
        );
        assert_eq!(values.len(), 2 * REQUEST_LOG_INSERT_COLUMNS);
        assert_eq!(sql.matches("), (").count(), 1);
        assert!(sql.ends_with("ON CONFLICT(id) DO NOTHING"));
    }

    #[test]
    fn request_log_insert_chunks_stay_below_portable_bind_ceiling() {
        let logs = (0..41)
            .map(|index| spool_request_log(&index.to_string()))
            .collect::<Vec<_>>();
        let bind_counts = logs
            .chunks(REQUEST_LOG_INSERT_CHUNK_ENTRIES)
            .map(|chunk| request_log_insert_chunk(chunk.iter()).1.len())
            .collect::<Vec<_>>();

        assert_eq!(bind_counts, vec![760, 760, 38]);
        assert!(bind_counts.into_iter().all(|count| count <= 999));
    }

    #[test]
    fn api_key_cache_capacity_and_reverse_index_remain_bounded() {
        let cache = ApiKeyCache::with_capacity(Duration::from_secs(60), 1);
        assert!(cache.insert_if_current(
            "token-1".to_string(),
            0,
            cached_api_key("key-1", "user-1", "token-1"),
            cached_user("user-1"),
            None,
        ));
        assert!(cache.insert_if_current(
            "token-2".to_string(),
            0,
            cached_api_key("key-2", "user-2", "token-2"),
            cached_user("user-2"),
            None,
        ));
        assert_eq!(cache.len(), 1);
        assert!(cache.get("token-2").is_some());
        cache.invalidate_by_key_id("key-2");
        assert_eq!(cache.len(), 0);
        assert!(!cache.key_id_index.contains_key("key-2"));
        assert!(!cache.user_id_index.contains_key("user-2"));
    }

    #[test]
    fn balance_cache_evicts_before_capacity_is_exceeded() {
        let cache = BalanceCache::with_capacity(Duration::from_secs(60), 1);
        assert!(cache.insert_if_current(
            "user-1".to_string(),
            0,
            UserBalance {
                user_id: "user-1".to_string(),
                balance_nano_usd: 1,
                balance_unlimited: false,
            },
        ));
        assert!(cache.insert_if_current(
            "user-2".to_string(),
            0,
            UserBalance {
                user_id: "user-2".to_string(),
                balance_nano_usd: 2,
                balance_unlimited: false,
            },
        ));
        assert_eq!(cache.len(), 1);
        assert!(cache.get("user-2").is_some());
    }

    #[test]
    fn request_log_counter_release_does_not_wrap_below_zero() {
        let counter = AtomicU64::new(10);

        atomic_saturating_sub(&counter, 11);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        atomic_saturating_sub(&counter, 1);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn request_log_admission_fails_before_spool_quota_is_overcommitted() {
        let temp = TempDir::new().unwrap();
        let quota = REQUEST_LOG_MIN_ENTRY_BYTES * 2;
        std::fs::write(
            temp.path().join("existing.json"),
            vec![0_u8; usize::try_from(quota - REQUEST_LOG_MIN_ENTRY_BYTES + 1).unwrap()],
        )
        .unwrap();
        let (broadcast, _) = tokio::sync::broadcast::channel(1);
        let batcher = RequestLogBatcher::new_with_limits(
            2,
            temp.path().to_path_buf(),
            quota,
            REQUEST_LOG_MIN_ENTRY_BYTES,
            broadcast,
            Arc::new(DashMap::new()),
        );
        assert!(!batcher.can_accept_terminal_log());
        assert!(matches!(
            batcher.ensure_log_capacity(),
            Err(RequestLogAdmissionError::QuotaExhausted)
        ));
    }

    #[test]
    fn request_log_admission_reports_unavailable_spool_path() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("not-a-directory");
        std::fs::write(&path, b"file").unwrap();
        let (broadcast, _) = tokio::sync::broadcast::channel(1);
        let batcher = RequestLogBatcher::new_with_limits(
            2,
            path,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
            broadcast,
            Arc::new(DashMap::new()),
        );
        assert!(matches!(
            batcher.ensure_log_capacity(),
            Err(RequestLogAdmissionError::Unavailable(_))
        ));
    }

    #[test]
    fn explicit_request_log_spool_directory_is_used_by_one_batcher() {
        let temp = TempDir::new().unwrap();
        let override_dir = temp.path().join("isolated-spool");
        let (broadcast, _) = tokio::sync::broadcast::channel(1);
        let batcher = RequestLogBatcher::new_with_spool_dir(
            2,
            Some(override_dir.clone()),
            broadcast,
            Arc::new(DashMap::new()),
        );

        assert_eq!(&*batcher.spool_dir, &override_dir);
        let reservation = batcher.reserve_terminal_log().unwrap();
        assert_eq!(std::fs::read_dir(&override_dir).unwrap().count(), 1);
        drop(reservation);
        assert_eq!(std::fs::read_dir(&override_dir).unwrap().count(), 0);
    }

    #[test]
    fn terminal_admission_rejects_entry_quota_below_minimum() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES - 1,
        );

        assert!(matches!(
            batcher.reserve_terminal_log(),
            Err(RequestLogAdmissionError::EntryQuotaTooSmall {
                configured,
                minimum,
            }) if configured == REQUEST_LOG_MIN_ENTRY_BYTES - 1
                && minimum == REQUEST_LOG_MIN_ENTRY_BYTES
        ));
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
        assert_eq!(batcher.admitted_bytes.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn reserved_oversize_log_rejects_without_partial_terminal_row() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let request_id = format!("request-{}", "\0💥".repeat(1_024));
        let mut log = terminal_request_log(&request_id);
        log.model = "💥".repeat(1_024);
        log.error_message = Some("oversize".repeat(2_048));
        let reservation = batcher.reserve_terminal_log().unwrap();
        arm_terminal(&batcher, &reservation, "oversize-fallback").await;

        assert!(matches!(
            batcher.push_reserved(log, reservation).await,
            Err(RequestLogAdmissionError::EntryTooLarge)
        ));

        let path = std::fs::read_dir(temp.path())
            .unwrap()
            .map(Result::unwrap)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap();
        let encoded = std::fs::read(path).unwrap();
        assert_eq!(
            batcher.spool_bytes.load(Ordering::Acquire),
            u64::try_from(encoded.len()).unwrap()
        );
        assert_eq!(
            batcher.admitted_bytes.load(Ordering::Acquire),
            u64::try_from(encoded.len()).unwrap()
        );
        let decoded: SpoolRequestLog = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.request_id.as_deref(), Some("oversize-fallback"));
        assert_eq!(decoded.model, "model-1");
        assert_eq!(decoded.status, "error");
        assert_eq!(
            decoded.error_code.as_deref(),
            Some("request_finalization_aborted")
        );
        assert_eq!(
            decoded.error_message.as_deref(),
            Some("request ended before terminal log persistence")
        );
        assert!(decoded.usage_breakdown_json.is_none());
    }

    #[tokio::test]
    async fn unreserved_internal_push_rejects_oversize_without_degradation() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let mut log = terminal_request_log("internal-producer");
        log.error_message = Some("oversize".repeat(2_048));

        assert!(matches!(
            batcher.push(log).await,
            Err(RequestLogAdmissionError::EntryTooLarge)
        ));
        assert_eq!(batcher.admitted_bytes.load(Ordering::Acquire), 0);
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .map(Result::unwrap)
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn reserved_write_recovers_after_transient_spool_failure() {
        let temp = TempDir::new().unwrap();
        let spool = temp.path().join("spool");
        let (broadcast, _) = tokio::sync::broadcast::channel(1);
        let batcher = RequestLogBatcher::new_with_limits(
            2,
            spool.clone(),
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
            broadcast,
            Arc::new(DashMap::new()),
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        arm_terminal(&batcher, &reservation, "request-retry").await;
        let displaced = temp.path().join("spool-displaced");
        std::fs::rename(&spool, &displaced).unwrap();
        std::fs::write(&spool, b"temporarily not a directory").unwrap();

        let writer_batcher = batcher.clone();
        let writer = tokio::spawn(async move {
            writer_batcher
                .push_reserved(terminal_request_log("request-retry"), reservation)
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while batcher.spool_healthy.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("writer must observe the transient spool failure");

        let flush_guard =
            tokio::time::timeout(Duration::from_millis(200), batcher.flush_lock.lock())
                .await
                .expect("retry sleep must not hold flush_lock");
        drop(flush_guard);
        std::fs::remove_file(&spool).unwrap();
        std::fs::rename(&displaced, &spool).unwrap();

        tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .expect("writer must recover after the spool path is restored")
            .unwrap()
            .unwrap();
        assert!(batcher.spool_healthy.load(Ordering::Acquire));
        assert_eq!(
            std::fs::read_dir(&spool)
                .unwrap()
                .map(Result::unwrap)
                .filter(
                    |entry| entry.path().extension().and_then(|value| value.to_str())
                        == Some("json")
                )
                .count(),
            1
        );
    }

    fn reservation_batcher(
        temp: &TempDir,
        quota: u64,
        reservation_bytes: u64,
    ) -> RequestLogBatcher {
        let (broadcast, _) = tokio::sync::broadcast::channel(1);
        RequestLogBatcher::new_with_limits(
            2,
            temp.path().to_path_buf(),
            quota,
            reservation_bytes,
            broadcast,
            Arc::new(DashMap::new()),
        )
    }

    #[test]
    fn reservation_clones_release_only_after_final_drop() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        let marker = reservation
            .inner
            .marker_path
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert!(marker.exists());
        let clone = reservation.clone();
        drop(reservation);
        assert!(matches!(
            batcher.reserve_terminal_log(),
            Err(RequestLogAdmissionError::QuotaExhausted)
        ));
        drop(clone);
        assert!(!marker.exists());
        assert!(batcher.reserve_terminal_log().is_ok());
    }

    #[tokio::test]
    async fn consumed_reservation_retains_only_actual_spool_bytes() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 3,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        arm_terminal(&batcher, &reservation, "consumed").await;
        reservation.claim(&batcher.admitted_bytes).unwrap();
        reservation.consume(20);
        drop(reservation);
        assert_eq!(batcher.admitted_bytes.load(Ordering::Acquire), 20);
        assert!(batcher.reserve_terminal_log().is_ok());
    }

    #[tokio::test]
    async fn armed_drop_promotes_fallback_to_stable_final_path() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        let stable_id = reservation.inner.stable_id.clone().unwrap();
        let marker = reservation
            .inner
            .marker_path
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        let final_path = reservation.inner.final_path.clone().unwrap();
        arm_terminal(&batcher, &reservation, "drop-fallback").await;

        drop(reservation);

        assert!(!marker.exists());
        assert!(final_path.exists());
        let encoded = std::fs::read(&final_path).unwrap();
        let decoded: SpoolRequestLog = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.id, stable_id);
        assert_eq!(decoded.request_id.as_deref(), Some("drop-fallback"));
        assert_eq!(decoded.status, "error");
        assert_eq!(
            batcher.admitted_bytes.load(Ordering::Acquire),
            u64::try_from(encoded.len()).unwrap()
        );
        assert_eq!(
            batcher.spool_bytes.load(Ordering::Acquire),
            u64::try_from(encoded.len()).unwrap()
        );
    }

    #[tokio::test]
    async fn startup_promotes_armed_marker_after_simulated_crash() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        let stable_id = reservation.inner.stable_id.clone().unwrap();
        let marker = reservation
            .inner
            .marker_path
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        let final_path = reservation.inner.final_path.clone().unwrap();
        arm_terminal(&batcher, &reservation, "restart-fallback").await;
        std::mem::forget(reservation);
        drop(batcher);

        assert!(marker.exists());
        assert!(!final_path.exists());
        let recovered = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        assert!(!marker.exists());
        assert!(final_path.exists());
        let encoded = std::fs::read(&final_path).unwrap();
        let decoded: SpoolRequestLog = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.id, stable_id);
        assert_eq!(decoded.request_id.as_deref(), Some("restart-fallback"));
        assert_eq!(
            recovered.spool_bytes.load(Ordering::Acquire),
            u64::try_from(encoded.len()).unwrap()
        );
    }

    #[tokio::test]
    async fn terminal_push_reuses_reserved_uuid_and_path() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 2,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        let stable_id = reservation.inner.stable_id.clone().unwrap();
        let marker = reservation
            .inner
            .marker_path
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        let final_path = reservation.inner.final_path.clone().unwrap();
        arm_terminal(&batcher, &reservation, "stable-terminal").await;
        let mut log = terminal_request_log("stable-terminal");
        log.usage_breakdown_json = Some(serde_json::json!({"input": 1, "output": 2}));
        log.billing_breakdown_json = Some(serde_json::json!({"charge_nano_usd": "3"}));

        batcher.push_reserved(log, reservation).await.unwrap();

        assert!(!marker.exists());
        assert!(final_path.exists());
        let decoded: SpoolRequestLog =
            serde_json::from_slice(&std::fs::read(final_path).unwrap()).unwrap();
        assert_eq!(decoded.id, stable_id);
        assert_eq!(decoded.status, "success");
        assert_eq!(decoded.input_tokens, Some(1));
        assert_eq!(decoded.output_tokens, Some(2));
        assert_eq!(decoded.charge_nano_usd.as_deref(), Some("3"));
        assert_eq!(
            decoded.usage_breakdown_json,
            Some(serde_json::json!({"input": 1, "output": 2}))
        );
        assert_eq!(
            decoded.billing_breakdown_json,
            Some(serde_json::json!({"charge_nano_usd": "3"}))
        );
        assert!(decoded.error_code.is_none());
    }

    #[tokio::test]
    async fn durable_cancel_removes_armed_fallback_and_releases_quota() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let reservation = batcher.reserve_terminal_log().unwrap();
        let marker = reservation
            .inner
            .marker_path
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        let final_path = reservation.inner.final_path.clone().unwrap();
        arm_terminal(&batcher, &reservation, "cancelled").await;

        batcher.cancel_reserved(&reservation).await.unwrap();
        drop(reservation);

        assert!(!marker.exists());
        assert!(!final_path.exists());
        assert_eq!(batcher.admitted_bytes.load(Ordering::Acquire), 0);
        assert!(batcher.reserve_terminal_log().is_ok());
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe_quota() {
        let temp = TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 3,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let batcher = batcher.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                batcher.reserve_terminal_log().ok()
            }));
        }
        barrier.wait();
        let reservations = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(reservations.len(), 3);
        assert_eq!(
            batcher.admitted_bytes.load(Ordering::Acquire),
            REQUEST_LOG_MIN_ENTRY_BYTES * 3
        );
        drop(reservations);
        assert_eq!(batcher.admitted_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn reservation_identity_distinguishes_tokens_but_matches_clones() {
        let temp = tempfile::TempDir::new().unwrap();
        let batcher = reservation_batcher(
            &temp,
            REQUEST_LOG_MIN_ENTRY_BYTES * 3,
            REQUEST_LOG_MIN_ENTRY_BYTES,
        );
        let first = batcher.reserve_terminal_log().unwrap();
        let clone = first.clone();
        let second = batcher.reserve_terminal_log().unwrap();

        assert!(first.same_reservation(&clone));
        assert!(!first.same_reservation(&second));
    }

    #[test]
    fn spool_request_log_round_trips_usage_into_insert_log() {
        let spool = spool_request_log("round-trip");
        let insert = spool.to_insert_log();
        assert_eq!(insert.request_id.as_deref(), Some("request-round-trip"));
        assert_eq!(insert.input_tokens, Some(1));
        assert_eq!(insert.output_tokens, Some(2));
        assert_eq!(insert.duration_ms, Some(10));
        assert_eq!(insert.ttfb_ms, Some(11));
        assert_eq!(insert.charge_nano_usd, Some(9));
        assert_eq!(insert.status, "success");
    }

    struct RecordingSink(std::sync::Mutex<Vec<SpoolRequestLog>>);

    #[async_trait::async_trait]
    impl MeteringSink for RecordingSink {
        async fn deliver(&self, entries: &[SpoolRequestLog]) -> Result<(), String> {
            self.0.lock().unwrap().extend(entries.iter().cloned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn ship_via_discovers_on_disk_files_when_memory_buffer_is_empty() {
        let temp = TempDir::new().unwrap();
        let log = spool_request_log("disk-only");
        let path = temp.path().join("00000000000000000001-disk-only.json");
        std::fs::write(&path, serde_json::to_vec(&log).unwrap()).unwrap();
        let (broadcast, _) = tokio::sync::broadcast::channel(1);
        let batcher = RequestLogBatcher::new_with_limits(
            2,
            temp.path().to_path_buf(),
            REQUEST_LOG_MIN_ENTRY_BYTES * 4,
            REQUEST_LOG_MIN_ENTRY_BYTES,
            broadcast,
            Arc::new(DashMap::new()),
        );
        let sink = RecordingSink(std::sync::Mutex::new(Vec::new()));
        let delivered = batcher.ship_via(10, &sink).await;
        assert_eq!(delivered, 1);
        let shipped = sink.0.lock().unwrap();
        assert_eq!(shipped.len(), 1);
        assert_eq!(shipped[0].id, "disk-only");
        assert!(!path.exists());
    }
