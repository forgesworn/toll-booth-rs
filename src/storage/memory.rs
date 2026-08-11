use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use super::traits::StorageBackend;
use crate::types::{Currency, DebitResult, StorageError, StoredInvoice};

/// Hard bound on stored invoices. Challenges are unauthenticated, so without
/// a cap an attacker could grow this map until the host runs out of memory.
/// When the cap is reached the oldest entries are evicted (FIFO).
const MAX_STORED_INVOICES: usize = 100_000;

#[derive(Debug)]
struct BalanceRecord {
    sat: i64,
    usd: i64,
    updated_at: Instant,
}

impl Default for BalanceRecord {
    fn default() -> Self {
        BalanceRecord {
            sat: 0,
            usd: 0,
            updated_at: Instant::now(),
        }
    }
}

impl BalanceRecord {
    fn get(&self, currency: Currency) -> i64 {
        match currency {
            Currency::Sat => self.sat,
            Currency::Usd => self.usd,
        }
    }

    fn set(&mut self, currency: Currency, value: i64) {
        match currency {
            Currency::Sat => self.sat = value,
            Currency::Usd => self.usd = value,
        }
        self.updated_at = Instant::now();
    }
}

// No timestamp here: settlement records are the replay guard for
// settle_with_credit and must never be pruned.
#[derive(Debug, Default)]
struct SettlementRecord {
    settled: bool,
    secret: Option<String>,
}

#[derive(Debug, Default)]
struct Inner {
    balances: HashMap<String, BalanceRecord>,
    settlements: HashMap<String, SettlementRecord>,
    invoices: HashMap<String, StoredInvoice>,
    /// Insertion order of invoice payment hashes, for FIFO eviction at the
    /// capacity cap. May contain keys already pruned from `invoices`; those
    /// are skipped on eviction.
    invoice_order: VecDeque<String>,
}

impl Inner {
    /// Evict oldest invoices until below [`MAX_STORED_INVOICES`].
    fn enforce_invoice_cap(&mut self) {
        while self.invoices.len() >= MAX_STORED_INVOICES {
            match self.invoice_order.pop_front() {
                Some(oldest) => {
                    self.invoices.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct MemoryStorage {
    inner: Mutex<Inner>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageBackend for MemoryStorage {
    fn credit(
        &self,
        payment_hash: &str,
        amount: i64,
        currency: Currency,
    ) -> Result<(), StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.balances.entry(payment_hash.to_string()).or_default();
        let new_balance = record
            .get(currency)
            .checked_add(amount)
            .ok_or_else(|| StorageError::Database("balance overflow on credit".into()))?;
        record.set(currency, new_balance);
        Ok(())
    }

    fn debit(
        &self,
        payment_hash: &str,
        amount: i64,
        currency: Currency,
    ) -> Result<DebitResult, StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.balances.entry(payment_hash.to_string()).or_default();
        let current = record.get(currency);
        if current >= amount {
            let remaining = current - amount;
            record.set(currency, remaining);
            Ok(DebitResult {
                success: true,
                remaining,
            })
        } else {
            Ok(DebitResult {
                success: false,
                remaining: current,
            })
        }
    }

    fn balance(&self, payment_hash: &str, currency: Currency) -> Result<i64, StorageError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner
            .balances
            .get(payment_hash)
            .map(|r| r.get(currency))
            .unwrap_or(0))
    }

    fn adjust_credits(
        &self,
        payment_hash: &str,
        delta: i64,
        currency: Currency,
    ) -> Result<i64, StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.balances.entry(payment_hash.to_string()).or_default();
        let new_balance = record
            .get(currency)
            .checked_add(delta)
            .ok_or_else(|| StorageError::Database("balance overflow on adjust".into()))?;
        record.set(currency, new_balance);
        Ok(new_balance)
    }

    fn settle(&self, payment_hash: &str) -> Result<bool, StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner
            .settlements
            .entry(payment_hash.to_string())
            .or_default();
        if record.settled {
            return Ok(false);
        }
        record.settled = true;
        Ok(true)
    }

    fn settle_with_credit(
        &self,
        payment_hash: &str,
        amount: i64,
        settlement_secret: Option<&str>,
        currency: Currency,
    ) -> Result<bool, StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let settlement = inner
            .settlements
            .entry(payment_hash.to_string())
            .or_default();
        if settlement.settled {
            return Ok(false);
        }
        settlement.settled = true;
        settlement.secret = settlement_secret.map(|s| s.to_string());
        let balance = inner.balances.entry(payment_hash.to_string()).or_default();
        let new_balance = balance
            .get(currency)
            .checked_add(amount)
            .ok_or_else(|| StorageError::Database("balance overflow on settle".into()))?;
        balance.set(currency, new_balance);
        Ok(true)
    }

    fn is_settled(&self, payment_hash: &str) -> Result<bool, StorageError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner
            .settlements
            .get(payment_hash)
            .map(|r| r.settled)
            .unwrap_or(false))
    }

    fn get_settlement_secret(&self, payment_hash: &str) -> Result<Option<String>, StorageError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner
            .settlements
            .get(payment_hash)
            .and_then(|r| r.secret.clone()))
    }

    fn store_invoice(&self, invoice: &StoredInvoice) -> Result<(), StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let is_new = !inner.invoices.contains_key(&invoice.payment_hash);
        if is_new {
            inner.enforce_invoice_cap();
            inner.invoice_order.push_back(invoice.payment_hash.clone());
        }
        inner
            .invoices
            .insert(invoice.payment_hash.clone(), invoice.clone());
        Ok(())
    }

    fn get_invoice(&self, payment_hash: &str) -> Result<Option<StoredInvoice>, StorageError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner.invoices.get(payment_hash).cloned())
    }

    fn get_invoice_for_status(
        &self,
        payment_hash: &str,
        status_token: &str,
    ) -> Result<Option<StoredInvoice>, StorageError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        match inner.invoices.get(payment_hash) {
            None => Ok(None),
            Some(invoice) => {
                let stored = invoice.status_token.as_bytes();
                let provided = status_token.as_bytes();
                // Both must be same length AND pass constant-time comparison
                if stored.len() == provided.len() && stored.ct_eq(provided).into() {
                    Ok(Some(invoice.clone()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn pending_invoice_count(&self, client_ip: &str) -> Result<u64, StorageError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let count = inner
            .invoices
            .values()
            .filter(|inv| inv.client_ip.as_deref() == Some(client_ip))
            .count();
        Ok(count as u64)
    }

    fn prune_expired_invoices(&self, max_age: Duration) -> Result<u64, StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let cutoff = chrono::Utc::now() - max_age;
        let before = inner.invoices.len();
        // Entries with an unparseable timestamp can never be aged; drop them
        // rather than letting them occupy capacity forever.
        inner.invoices.retain(|_, inv| {
            chrono::DateTime::parse_from_rfc3339(&inv.created_at)
                .map(|created| created > cutoff)
                .unwrap_or(false)
        });
        Ok((before - inner.invoices.len()) as u64)
    }

    fn prune_stale_records(&self, max_age: Duration) -> Result<u64, StorageError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let now = Instant::now();
        let before = inner.balances.len();
        // Only fully-drained balance records are safe to drop: removing a
        // record with a remaining balance would destroy funds, and removing
        // settlement records is never safe because they are the replay guard
        // for settle_with_credit.
        inner.balances.retain(|_, rec| {
            rec.sat != 0 || rec.usd != 0 || now.duration_since(rec.updated_at) < max_age
        });
        Ok((before - inner.balances.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> String {
        format!("{:0>64}", n)
    }

    fn make_invoice(
        payment_hash: &str,
        status_token: &str,
        client_ip: Option<&str>,
    ) -> StoredInvoice {
        StoredInvoice {
            payment_hash: payment_hash.to_string(),
            bolt11: "lnbc1...".to_string(),
            amount_sats: 1000,
            macaroon: "macaroon_value".to_string(),
            status_token: status_token.to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            client_ip: client_ip.map(|s| s.to_string()),
        }
    }

    #[test]
    fn credit_and_balance() {
        let store = MemoryStorage::new();
        let h = hash(1);
        store.credit(&h, 500, Currency::Sat).unwrap();
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 500);
    }

    #[test]
    fn debit_sufficient() {
        let store = MemoryStorage::new();
        let h = hash(2);
        store.credit(&h, 1000, Currency::Sat).unwrap();
        let result = store.debit(&h, 300, Currency::Sat).unwrap();
        assert!(result.success);
        assert_eq!(result.remaining, 700);
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 700);
    }

    #[test]
    fn debit_insufficient() {
        let store = MemoryStorage::new();
        let h = hash(3);
        store.credit(&h, 100, Currency::Sat).unwrap();
        let result = store.debit(&h, 300, Currency::Sat).unwrap();
        assert!(!result.success);
        assert_eq!(result.remaining, 100);
        // Balance unchanged
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 100);
    }

    #[test]
    fn settle_once() {
        let store = MemoryStorage::new();
        let h = hash(4);
        assert!(store.settle(&h).unwrap());
        // Second call returns false
        assert!(!store.settle(&h).unwrap());
        assert!(store.is_settled(&h).unwrap());
    }

    #[test]
    fn settle_with_credit_credits_balance_stores_secret_rejects_second() {
        let store = MemoryStorage::new();
        let h = hash(5);
        let secret = "preimage_secret";

        let settled = store
            .settle_with_credit(&h, 2000, Some(secret), Currency::Sat)
            .unwrap();
        assert!(settled);
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 2000);
        assert_eq!(
            store.get_settlement_secret(&h).unwrap(),
            Some(secret.to_string())
        );

        // Second settle should be rejected
        let settled_again = store
            .settle_with_credit(&h, 2000, Some(secret), Currency::Sat)
            .unwrap();
        assert!(!settled_again);
        // Balance should not have doubled
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 2000);
    }

    #[test]
    fn adjust_credits() {
        let store = MemoryStorage::new();
        let h = hash(6);
        store.credit(&h, 500, Currency::Sat).unwrap();

        let after_positive = store.adjust_credits(&h, 200, Currency::Sat).unwrap();
        assert_eq!(after_positive, 700);

        let after_negative = store.adjust_credits(&h, -100, Currency::Sat).unwrap();
        assert_eq!(after_negative, 600);

        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 600);
    }

    #[test]
    fn dual_currency() {
        let store = MemoryStorage::new();
        let h = hash(7);
        store.credit(&h, 5000, Currency::Sat).unwrap();
        store.credit(&h, 199, Currency::Usd).unwrap();

        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 5000);
        assert_eq!(store.balance(&h, Currency::Usd).unwrap(), 199);

        store.debit(&h, 1000, Currency::Sat).unwrap();
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 4000);
        assert_eq!(store.balance(&h, Currency::Usd).unwrap(), 199);
    }

    #[test]
    fn invoice_storage() {
        let store = MemoryStorage::new();
        let h = hash(8);
        let inv = make_invoice(&h, "tok_abc", Some("1.2.3.4"));

        store.store_invoice(&inv).unwrap();
        let retrieved = store
            .get_invoice(&h)
            .unwrap()
            .expect("invoice should exist");
        assert_eq!(retrieved.payment_hash, h);
        assert_eq!(retrieved.amount_sats, 1000);

        // Non-existent
        assert!(store.get_invoice(&hash(99)).unwrap().is_none());
    }

    #[test]
    fn invoice_status_token_timing_safe() {
        let store = MemoryStorage::new();
        let h = hash(9);
        let correct_token = "correct_status_token_32chars_pad";
        let wrong_token = "wrong_status_token_xxxxxxxxxxxx_";
        let inv = make_invoice(&h, correct_token, Some("10.0.0.1"));
        store.store_invoice(&inv).unwrap();

        // Correct token returns invoice
        let found = store.get_invoice_for_status(&h, correct_token).unwrap();
        assert!(found.is_some());

        // Wrong token returns None
        let not_found = store.get_invoice_for_status(&h, wrong_token).unwrap();
        assert!(not_found.is_none());

        // Different length token returns None (avoids short-circuit timing leak)
        let short_token = "short";
        let not_found_short = store.get_invoice_for_status(&h, short_token).unwrap();
        assert!(not_found_short.is_none());
    }

    // -- Security: balance overflow protection --

    #[test]
    fn credit_overflow_returns_error() {
        let store = MemoryStorage::new();
        let h = hash(20);
        store.credit(&h, i64::MAX, Currency::Sat).unwrap();
        // Adding 1 more should overflow and return an error, not wrap
        let result = store.credit(&h, 1, Currency::Sat);
        assert!(result.is_err(), "credit must reject i64 overflow");
        // Balance should remain at i64::MAX (unchanged)
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), i64::MAX);
    }

    #[test]
    fn adjust_credits_overflow_returns_error() {
        let store = MemoryStorage::new();
        let h = hash(21);
        store.credit(&h, i64::MAX, Currency::Sat).unwrap();
        let result = store.adjust_credits(&h, 1, Currency::Sat);
        assert!(result.is_err(), "adjust_credits must reject i64 overflow");
        // Balance unchanged
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), i64::MAX);
    }

    #[test]
    fn settle_with_credit_overflow_returns_error() {
        let store = MemoryStorage::new();
        let h = hash(22);
        // Pre-credit to near max
        store.credit(&h, i64::MAX, Currency::Sat).unwrap();
        // Settling with additional credit should overflow
        let result = store.settle_with_credit(&h, 1, Some("secret"), Currency::Sat);
        assert!(
            result.is_err(),
            "settle_with_credit must reject i64 overflow"
        );
    }

    // -- Security: invoice pruning and capacity bounds (unauthenticated DoS) --

    #[test]
    fn prune_expired_invoices_removes_old_keeps_recent() {
        let store = MemoryStorage::new();
        let old_h = hash(30);
        let new_h = hash(31);

        let mut old_inv = make_invoice(&old_h, "tok_old", Some("1.2.3.4"));
        old_inv.created_at = "2020-01-01T00:00:00+00:00".to_string();
        let mut new_inv = make_invoice(&new_h, "tok_new", Some("1.2.3.4"));
        new_inv.created_at = chrono::Utc::now().to_rfc3339();

        store.store_invoice(&old_inv).unwrap();
        store.store_invoice(&new_inv).unwrap();

        let removed = store
            .prune_expired_invoices(std::time::Duration::from_secs(24 * 60 * 60))
            .unwrap();
        assert_eq!(removed, 1, "exactly the stale invoice should be pruned");
        assert!(store.get_invoice(&old_h).unwrap().is_none());
        assert!(store.get_invoice(&new_h).unwrap().is_some());
    }

    #[test]
    fn prune_expired_invoices_drops_unparseable_timestamps() {
        let store = MemoryStorage::new();
        let h = hash(32);
        let mut inv = make_invoice(&h, "tok_bad", None);
        inv.created_at = "not-a-timestamp".to_string();
        store.store_invoice(&inv).unwrap();

        let removed = store
            .prune_expired_invoices(std::time::Duration::from_secs(60))
            .unwrap();
        assert_eq!(removed, 1, "unparseable created_at must not linger");
        assert!(store.get_invoice(&h).unwrap().is_none());
    }

    #[test]
    fn store_invoice_evicts_oldest_at_capacity() {
        let store = MemoryStorage::new();
        // Fill to the cap
        for i in 0..super::MAX_STORED_INVOICES {
            let h = format!("{:0>64}", format!("{:x}", i));
            let inv = make_invoice(&h, "tok", Some("9.9.9.9"));
            store.store_invoice(&inv).unwrap();
        }
        // One more insert must evict the oldest rather than grow unbounded.
        // ("f".repeat(64) cannot collide with the zero-padded hex keys above,
        // which only reach 0x186a0.)
        let overflow_hash = "f".repeat(64);
        store
            .store_invoice(&make_invoice(&overflow_hash, "tok", Some("9.9.9.9")))
            .unwrap();

        let first_hash = format!("{:0>64}", format!("{:x}", 0));
        assert!(
            store.get_invoice(&first_hash).unwrap().is_none(),
            "oldest invoice should have been evicted"
        );
        assert!(store.get_invoice(&overflow_hash).unwrap().is_some());
        assert_eq!(
            store.pending_invoice_count("9.9.9.9").unwrap(),
            super::MAX_STORED_INVOICES as u64,
            "invoice count must stay at the cap"
        );
    }

    #[test]
    fn prune_stale_records_removes_only_drained_balances() {
        let store = MemoryStorage::new();
        let drained = hash(34);
        let funded = hash(35);

        // A record that was used and fully drained
        store.credit(&drained, 100, Currency::Sat).unwrap();
        store.debit(&drained, 100, Currency::Sat).unwrap();
        // A record with funds remaining
        store.credit(&funded, 100, Currency::Sat).unwrap();

        let removed = store
            .prune_stale_records(std::time::Duration::from_nanos(0))
            .unwrap();
        assert_eq!(removed, 1, "only the drained record should be pruned");
        assert_eq!(store.balance(&funded, Currency::Sat).unwrap(), 100);
    }

    #[test]
    fn prune_stale_records_never_touches_settlements() {
        let store = MemoryStorage::new();
        let h = hash(36);
        store
            .settle_with_credit(&h, 500, Some("secret"), Currency::Sat)
            .unwrap();
        store.debit(&h, 500, Currency::Sat).unwrap();

        store
            .prune_stale_records(std::time::Duration::from_nanos(0))
            .unwrap();

        assert!(
            store.is_settled(&h).unwrap(),
            "settlement record is the replay guard and must survive pruning"
        );
        // Replay must still be rejected after pruning
        let settled_again = store
            .settle_with_credit(&h, 500, Some("secret"), Currency::Sat)
            .unwrap();
        assert!(!settled_again, "replay after prune must not re-credit");
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 0);
    }
}

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use crate::types::StorageError;

    /// Storage wrapper that delegates to [`MemoryStorage`] but can be told to
    /// fail `debit` and/or `settle`, simulating a storage outage.
    pub(crate) struct FlakyStorage {
        inner: MemoryStorage,
        pub fail_debit: bool,
        pub fail_settle: bool,
    }

    impl FlakyStorage {
        pub(crate) fn new(fail_debit: bool, fail_settle: bool) -> Self {
            FlakyStorage {
                inner: MemoryStorage::new(),
                fail_debit,
                fail_settle,
            }
        }
    }

    fn outage<T>() -> Result<T, StorageError> {
        Err(StorageError::Database("simulated storage outage".into()))
    }

    impl StorageBackend for FlakyStorage {
        fn credit(
            &self,
            payment_hash: &str,
            amount: i64,
            currency: Currency,
        ) -> Result<(), StorageError> {
            self.inner.credit(payment_hash, amount, currency)
        }

        fn debit(
            &self,
            payment_hash: &str,
            amount: i64,
            currency: Currency,
        ) -> Result<DebitResult, StorageError> {
            if self.fail_debit {
                return outage();
            }
            self.inner.debit(payment_hash, amount, currency)
        }

        fn balance(&self, payment_hash: &str, currency: Currency) -> Result<i64, StorageError> {
            self.inner.balance(payment_hash, currency)
        }

        fn adjust_credits(
            &self,
            payment_hash: &str,
            delta: i64,
            currency: Currency,
        ) -> Result<i64, StorageError> {
            self.inner.adjust_credits(payment_hash, delta, currency)
        }

        fn settle(&self, payment_hash: &str) -> Result<bool, StorageError> {
            if self.fail_settle {
                return outage();
            }
            self.inner.settle(payment_hash)
        }

        fn settle_with_credit(
            &self,
            payment_hash: &str,
            amount: i64,
            settlement_secret: Option<&str>,
            currency: Currency,
        ) -> Result<bool, StorageError> {
            self.inner
                .settle_with_credit(payment_hash, amount, settlement_secret, currency)
        }

        fn is_settled(&self, payment_hash: &str) -> Result<bool, StorageError> {
            self.inner.is_settled(payment_hash)
        }

        fn get_settlement_secret(
            &self,
            payment_hash: &str,
        ) -> Result<Option<String>, StorageError> {
            self.inner.get_settlement_secret(payment_hash)
        }

        fn store_invoice(&self, invoice: &StoredInvoice) -> Result<(), StorageError> {
            self.inner.store_invoice(invoice)
        }

        fn get_invoice(&self, payment_hash: &str) -> Result<Option<StoredInvoice>, StorageError> {
            self.inner.get_invoice(payment_hash)
        }

        fn get_invoice_for_status(
            &self,
            payment_hash: &str,
            status_token: &str,
        ) -> Result<Option<StoredInvoice>, StorageError> {
            self.inner
                .get_invoice_for_status(payment_hash, status_token)
        }

        fn pending_invoice_count(&self, client_ip: &str) -> Result<u64, StorageError> {
            self.inner.pending_invoice_count(client_ip)
        }

        fn prune_expired_invoices(
            &self,
            max_age: std::time::Duration,
        ) -> Result<u64, StorageError> {
            self.inner.prune_expired_invoices(max_age)
        }

        fn prune_stale_records(&self, max_age: std::time::Duration) -> Result<u64, StorageError> {
            self.inner.prune_stale_records(max_age)
        }
    }
}
