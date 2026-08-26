//! Balance and billing-ledger operations for `UserStore`: row-locked user and
//! sub-account charging, admin adjustments, and transfers.

use super::utils::parse_nano_usd;
use super::{
    BillingError, BillingErrorKind, UserBalance, UserStore,
};
use chrono::Utc;
use sea_orm::Value as SeaValue;
use sea_orm::{ConnectionTrait, DatabaseTransaction, QueryResult, TransactionTrait};
use serde_json::Value;

#[derive(Clone, Copy)]
pub(super) struct LockedUserBalance {
    pub(super) balance: i128,
    pub(super) unlimited: bool,
    pub(super) enabled: bool,
}

pub(super) struct LockedApiKeyBalance {
    pub(super) user_id: String,
    pub(super) balance: i128,
    pub(super) sub_account_enabled: bool,
}

impl UserStore {
    pub(super) async fn lock_user_balance_tx(
        &self,
        tx: &DatabaseTransaction,
        user_id: &str,
    ) -> Result<LockedUserBalance, BillingError> {
        let sql = if self.db.is_postgres() {
            "SELECT balance_nano_usd, balance_unlimited, enabled FROM users WHERE id = $1 FOR UPDATE"
        } else {
            "SELECT balance_nano_usd, balance_unlimited, enabled FROM users WHERE id = $1"
        };
        let row = tx
            .query_one(self.db.stmt(sql, vec![user_id.into()]))
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            .ok_or_else(|| BillingError::new(BillingErrorKind::NotFound, "user not found"))?;
        let raw: String = row
            .try_get("", "balance_nano_usd")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        let balance = parse_nano_usd(&raw)
            .map_err(|e| BillingError::new(BillingErrorKind::InvalidStoredBalance, e))?;
        let unlimited = row
            .try_get::<i32>("", "balance_unlimited")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            == 1;
        let enabled = row
            .try_get::<i32>("", "enabled")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            == 1;
        Ok(LockedUserBalance {
            balance,
            unlimited,
            enabled,
        })
    }

    pub(super) async fn lock_api_key_balance_tx(
        &self,
        tx: &DatabaseTransaction,
        api_key_id: &str,
        expected_user_id: &str,
    ) -> Result<LockedApiKeyBalance, BillingError> {
        let sql = if self.db.is_postgres() {
            "SELECT user_id, sub_account_enabled, sub_account_balance_nano FROM api_keys WHERE id = $1 FOR UPDATE"
        } else {
            "SELECT user_id, sub_account_enabled, sub_account_balance_nano FROM api_keys WHERE id = $1"
        };
        let row = tx
            .query_one(self.db.stmt(sql, vec![api_key_id.into()]))
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            .ok_or_else(|| BillingError::new(BillingErrorKind::NotFound, "api key not found"))?;
        let user_id: String = row
            .try_get("", "user_id")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        if user_id != expected_user_id {
            return Err(BillingError::new(
                BillingErrorKind::NotFound,
                "api key owner does not match user",
            ));
        }
        let raw: String = row
            .try_get("", "sub_account_balance_nano")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        let balance = parse_nano_usd(&raw)
            .map_err(|e| BillingError::new(BillingErrorKind::InvalidStoredBalance, e))?;
        let sub_account_enabled = row
            .try_get::<i32>("", "sub_account_enabled")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            == 1;
        Ok(LockedApiKeyBalance {
            user_id,
            balance,
            sub_account_enabled,
        })
    }

    fn user_balance_from_row(row: &QueryResult) -> Result<UserBalance, String> {
        let balance_raw: String = row
            .try_get("", "balance_nano_usd")
            .map_err(|e| e.to_string())?;
        Ok(UserBalance {
            user_id: row.try_get("", "id").map_err(|e| e.to_string())?,
            balance_nano_usd: parse_nano_usd(&balance_raw)?,
            balance_unlimited: row
                .try_get::<i32>("", "balance_unlimited")
                .map_err(|e| e.to_string())?
                == 1,
        })
    }

    async fn load_user_balance(&self, user_id: &str) -> Result<Option<UserBalance>, String> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT id, balance_nano_usd, balance_unlimited FROM users WHERE id = $1",
                vec![user_id.into()],
            ))
            .await
            .map_err(|e| e.to_string())?;
        row.map(|row| Self::user_balance_from_row(&row)).transpose()
    }

    pub async fn get_user_balance(&self, user_id: &str) -> Result<Option<UserBalance>, String> {
        loop {
            if let Some(cached) = self.balance_cache.get(user_id) {
                return Ok(Some(cached));
            }
            let generation = self.balance_cache.current_generation();
            let Some(balance) = self.load_user_balance(user_id).await? else {
                if self.balance_cache.current_generation() != generation {
                    continue;
                }
                return Ok(None);
            };
            if !self.balance_cache.insert_if_current(
                user_id.to_string(),
                generation,
                balance.clone(),
            ) {
                continue;
            }
            return Ok(Some(balance));
        }
    }

    /// Replica preflight (M7): persisted balance without the 30s dashboard cache.
    pub async fn get_user_balance_uncached(
        &self,
        user_id: &str,
    ) -> Result<Option<UserBalance>, String> {
        self.load_user_balance(user_id).await
    }

    pub async fn ensure_user_can_spend(&self, user_id: &str) -> Result<(), BillingError> {
        let row = self
            .db
            .read()
            .query_one(self.db.stmt(
                "SELECT balance_nano_usd, balance_unlimited FROM users WHERE id = $1",
                vec![user_id.into()],
            ))
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            .ok_or_else(|| BillingError::new(BillingErrorKind::NotFound, "user not found"))?;
        let raw: String = row
            .try_get("", "balance_nano_usd")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        let balance = parse_nano_usd(&raw)
            .map_err(|e| BillingError::new(BillingErrorKind::InvalidStoredBalance, e))?;
        let unlimited = row
            .try_get::<i32>("", "balance_unlimited")
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?
            == 1;

        if unlimited {
            return Ok(());
        }
        if balance <= 0 {
            return Err(BillingError::new(
                BillingErrorKind::InsufficientBalance,
                "insufficient balance",
            ));
        }
        Ok(())
    }

    pub async fn charge_user_balance_nano(
        &self,
        user_id: &str,
        amount_nano_usd: i128,
        meta: &Value,
    ) -> Result<(), BillingError> {
        if amount_nano_usd <= 0 {
            return Ok(());
        }
        if meta
            .get("request_id")
            .and_then(Value::as_str)
            .is_none_or(|request_id| request_id.trim().is_empty())
        {
            return Err(BillingError::new(
                BillingErrorKind::Internal,
                "request charge metadata is missing request_id",
            ));
        }
        self.charge_user_balance_nano_inner(user_id, amount_nano_usd, meta)
            .await
    }

    async fn charge_user_balance_nano_inner(
        &self,
        user_id: &str,
        amount_nano_usd: i128,
        meta: &Value,
    ) -> Result<(), BillingError> {
        let _write_guard = self.db.write().await;
        let tx = _write_guard
            .begin()
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        let user = self.lock_user_balance_tx(&tx, user_id).await?;
        if user.unlimited {
            tx.commit()
                .await
                .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
            return Ok(());
        }

        let next_balance = user.balance.checked_sub(amount_nano_usd).ok_or_else(|| {
            BillingError::new(BillingErrorKind::Overflow, "balance subtraction overflow")
        })?;

        let now = Utc::now().to_rfc3339();
        tx.execute(self.db.stmt(
            "UPDATE users SET balance_nano_usd = $1, updated_at = $2 WHERE id = $3",
            vec![
                next_balance.to_string().into(),
                now.clone().into(),
                user_id.into(),
            ],
        ))
        .await
        .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;

        self.insert_billing_ledger_tx(
            &tx,
            user_id,
            "request_charge",
            -amount_nano_usd,
            Some(next_balance),
            meta,
            &now,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        self.balance_cache.invalidate(user_id);
        Ok(())
    }

    pub async fn admin_adjust_user_balance(
        &self,
        user_id: &str,
        balance_nano_usd: Option<String>,
        balance_unlimited: Option<bool>,
        actor_user_id: &str,
    ) -> Result<(), String> {
        if balance_nano_usd.is_none() && balance_unlimited.is_none() {
            return Ok(());
        }

        let _write_guard = self.db.write().await;
        let tx = _write_guard.begin().await.map_err(|e| e.to_string())?;
        let current = self
            .lock_user_balance_tx(&tx, user_id)
            .await
            .map_err(|e| e.message)?;
        let current_balance = current.balance;
        let current_unlimited = current.unlimited;

        let new_balance = if let Some(balance_raw) = balance_nano_usd {
            parse_nano_usd(&balance_raw)?
        } else {
            current_balance
        };
        let new_unlimited = balance_unlimited.unwrap_or(current_unlimited);

        let now = Utc::now().to_rfc3339();
        tx.execute(self.db.stmt(
            "UPDATE users SET balance_nano_usd = $1, balance_unlimited = $2, updated_at = $3 WHERE id = $4",
            vec![
                new_balance.to_string().into(),
                SeaValue::Int(Some(if new_unlimited { 1 } else { 0 })),
                now.clone().into(),
                user_id.into(),
            ],
        ))
        .await
        .map_err(|e| e.to_string())?;

        let delta = new_balance
            .checked_sub(current_balance)
            .ok_or_else(|| "balance delta overflow".to_string())?;
        let meta = serde_json::json!({
            "actor_user_id": actor_user_id,
            "before_balance_nano_usd": current_balance.to_string(),
            "after_balance_nano_usd": new_balance.to_string(),
            "before_balance_unlimited": current_unlimited,
            "after_balance_unlimited": new_unlimited,
        });

        self.insert_billing_ledger_tx(
            &tx,
            user_id,
            "admin_adjustment",
            delta,
            Some(new_balance),
            &meta,
            &now,
        )
        .await
        .map_err(|e| e.message)?;

        tx.commit().await.map_err(|e| e.to_string())?;
        self.balance_cache.invalidate(user_id);
        Ok(())
    }

    pub async fn charge_sub_account_balance_nano(
        &self,
        api_key_id: &str,
        user_id: &str,
        amount_nano_usd: i128,
        meta: &Value,
    ) -> Result<(), BillingError> {
        if amount_nano_usd <= 0 {
            return Ok(());
        }
        if meta
            .get("request_id")
            .and_then(Value::as_str)
            .is_none_or(|request_id| request_id.trim().is_empty())
        {
            return Err(BillingError::new(
                BillingErrorKind::Internal,
                "request charge metadata is missing request_id",
            ));
        }
        let _write_guard = self.db.write().await;
        let tx = _write_guard
            .begin()
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;

        let user = self.lock_user_balance_tx(&tx, user_id).await?;
        let key = match self.lock_api_key_balance_tx(&tx, api_key_id, user_id).await {
            Ok(key) => Some(key),
            Err(error) if error.kind == BillingErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if key.as_ref().is_none_or(|key| !key.sub_account_enabled) {
            if user.unlimited {
                tx.commit()
                    .await
                    .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
                return Ok(());
            }
            let next_balance = user.balance.checked_sub(amount_nano_usd).ok_or_else(|| {
                BillingError::new(BillingErrorKind::Overflow, "balance subtraction overflow")
            })?;
            let now = Utc::now().to_rfc3339();
            tx.execute(self.db.stmt(
                "UPDATE users SET balance_nano_usd = $1, updated_at = $2 WHERE id = $3",
                vec![
                    next_balance.to_string().into(),
                    now.clone().into(),
                    user_id.into(),
                ],
            ))
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
            self.insert_billing_ledger_tx(
                &tx,
                user_id,
                "request_charge",
                -amount_nano_usd,
                Some(next_balance),
                meta,
                &now,
            )
            .await?;
            tx.commit()
                .await
                .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
            self.balance_cache.invalidate(user_id);
            self.api_key_cache.invalidate_by_key_id(api_key_id);
            return Ok(());
        }
        let key = key.expect("enabled sub-account key must be present");
        let next_balance = key.balance.checked_sub(amount_nano_usd).ok_or_else(|| {
            BillingError::new(
                BillingErrorKind::Overflow,
                "sub-account balance subtraction overflow",
            )
        })?;

        let now = Utc::now().to_rfc3339();
        tx.execute(self.db.stmt(
            "UPDATE api_keys SET sub_account_balance_nano = $1 WHERE id = $2",
            vec![next_balance.to_string().into(), api_key_id.into()],
        ))
        .await
        .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;

        self.insert_billing_ledger_tx(
            &tx,
            user_id,
            "api_key_charge",
            -amount_nano_usd,
            Some(next_balance),
            meta,
            &now,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        self.api_key_cache.invalidate_by_key_id(api_key_id);
        Ok(())
    }

    pub async fn transfer_to_sub_account(
        &self,
        api_key_id: &str,
        user_id: &str,
        amount_nano_usd: i128,
    ) -> Result<(i128, i128), BillingError> {
        if amount_nano_usd <= 0 {
            return Err(BillingError::new(
                BillingErrorKind::Internal,
                "transfer amount must be positive",
            ));
        }

        let _write_guard = self.db.write().await;
        let tx = _write_guard
            .begin()
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;

        let user = self.lock_user_balance_tx(&tx, user_id).await?;
        let key = self
            .lock_api_key_balance_tx(&tx, api_key_id, user_id)
            .await?;
        if !key.sub_account_enabled {
            return Err(BillingError::new(
                BillingErrorKind::Internal,
                "sub-account not enabled on this key",
            ));
        }

        let new_user_balance = if user.unlimited {
            user.balance
        } else {
            let next = user.balance.checked_sub(amount_nano_usd).ok_or_else(|| {
                BillingError::new(BillingErrorKind::Overflow, "user balance overflow")
            })?;
            if next < 0 {
                return Err(BillingError::new(
                    BillingErrorKind::InsufficientBalance,
                    "insufficient balance for transfer",
                ));
            }
            tx.execute(self.db.stmt(
                "UPDATE users SET balance_nano_usd = $1 WHERE id = $2",
                vec![next.to_string().into(), user_id.into()],
            ))
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
            next
        };

        let new_key_balance = key.balance.checked_add(amount_nano_usd).ok_or_else(|| {
            BillingError::new(BillingErrorKind::Overflow, "sub-account balance overflow")
        })?;

        tx.execute(self.db.stmt(
            "UPDATE api_keys SET sub_account_balance_nano = $1 WHERE id = $2",
            vec![new_key_balance.to_string().into(), api_key_id.into()],
        ))
        .await
        .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;

        let now = Utc::now().to_rfc3339();
        if !user.unlimited {
            self.insert_billing_ledger_tx(
                &tx,
                user_id,
                "sub_account_transfer_out",
                -amount_nano_usd,
                Some(new_user_balance),
                &serde_json::json!({ "api_key_id": api_key_id }),
                &now,
            )
            .await?;
        }
        self.insert_billing_ledger_tx(
            &tx,
            user_id,
            "sub_account_transfer_in",
            amount_nano_usd,
            Some(new_key_balance),
            &serde_json::json!({ "api_key_id": api_key_id }),
            &now,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        self.balance_cache.invalidate(user_id);
        self.api_key_cache.invalidate_by_key_id(api_key_id);
        Ok((new_key_balance, new_user_balance))
    }

    pub async fn ensure_sub_account_can_spend(&self, api_key_id: &str) -> Result<(), BillingError> {
        let key = self
            .get_api_key_by_id(api_key_id)
            .await
            .map_err(|e| BillingError::new(BillingErrorKind::Internal, e))?
            .ok_or_else(|| BillingError::new(BillingErrorKind::NotFound, "api key not found"))?;
        let balance = parse_nano_usd(&key.sub_account_balance_nano)
            .map_err(|e| BillingError::new(BillingErrorKind::InvalidStoredBalance, e))?;
        if balance <= 0 {
            return Err(BillingError::new(
                BillingErrorKind::InsufficientBalance,
                "insufficient balance",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn insert_billing_ledger_tx(
        &self,
        tx: &DatabaseTransaction,
        user_id: &str,
        kind: &str,
        delta_nano_usd: i128,
        balance_after_nano_usd: Option<i128>,
        meta: &Value,
        created_at_rfc3339: &str,
    ) -> Result<(), BillingError> {
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute(self.db.stmt(
            r#"INSERT INTO billing_ledger (id, user_id, kind, delta_nano_usd, balance_after_nano_usd, meta_json, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            vec![
                id.into(),
                user_id.into(),
                kind.into(),
                delta_nano_usd.to_string().into(),
                balance_after_nano_usd.map(|v| v.to_string()).into(),
                meta.to_string().into(),
                created_at_rfc3339.into(),
            ],
        ))
        .await
        .map_err(|e| BillingError::new(BillingErrorKind::Internal, e.to_string()))?;
        Ok(())
    }
}
