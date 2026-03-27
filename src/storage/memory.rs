use std::collections::HashMap;
use std::sync::Mutex;
use subtle::ConstantTimeEq;

use crate::types::{Currency, DebitResult, StorageError, StoredInvoice};
use super::traits::StorageBackend;

#[derive(Debug, Default)]
struct BalanceRecord {
    sat: i64,
    usd: i64,
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
    }
}

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
    fn credit(&self, payment_hash: &str, amount: i64, currency: Currency) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.balances.entry(payment_hash.to_string()).or_default();
        record.set(currency, record.get(currency) + amount);
        Ok(())
    }

    fn debit(&self, payment_hash: &str, amount: i64, currency: Currency) -> Result<DebitResult, StorageError> {
        let mut inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.balances.entry(payment_hash.to_string()).or_default();
        let current = record.get(currency);
        if current >= amount {
            let remaining = current - amount;
            record.set(currency, remaining);
            Ok(DebitResult { success: true, remaining })
        } else {
            Ok(DebitResult { success: false, remaining: current })
        }
    }

    fn balance(&self, payment_hash: &str, currency: Currency) -> Result<i64, StorageError> {
        let inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner.balances.get(payment_hash).map(|r| r.get(currency)).unwrap_or(0))
    }

    fn adjust_credits(&self, payment_hash: &str, delta: i64, currency: Currency) -> Result<i64, StorageError> {
        let mut inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.balances.entry(payment_hash.to_string()).or_default();
        let new_balance = record.get(currency) + delta;
        record.set(currency, new_balance);
        Ok(new_balance)
    }

    fn settle(&self, payment_hash: &str) -> Result<bool, StorageError> {
        let mut inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        let record = inner.settlements.entry(payment_hash.to_string()).or_default();
        if record.settled {
            return Ok(false);
        }
        record.settled = true;
        Ok(true)
    }

    fn settle_with_credit(&self, payment_hash: &str, amount: i64, settlement_secret: Option<&str>, currency: Currency) -> Result<bool, StorageError> {
        let mut inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        let settlement = inner.settlements.entry(payment_hash.to_string()).or_default();
        if settlement.settled {
            return Ok(false);
        }
        settlement.settled = true;
        settlement.secret = settlement_secret.map(|s| s.to_string());
        let balance = inner.balances.entry(payment_hash.to_string()).or_default();
        balance.set(currency, balance.get(currency) + amount);
        Ok(true)
    }

    fn is_settled(&self, payment_hash: &str) -> Result<bool, StorageError> {
        let inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner.settlements.get(payment_hash).map(|r| r.settled).unwrap_or(false))
    }

    fn get_settlement_secret(&self, payment_hash: &str) -> Result<Option<String>, StorageError> {
        let inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner.settlements.get(payment_hash).and_then(|r| r.secret.clone()))
    }

    fn store_invoice(&self, invoice: &StoredInvoice) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        inner.invoices.insert(invoice.payment_hash.clone(), invoice.clone());
        Ok(())
    }

    fn get_invoice(&self, payment_hash: &str) -> Result<Option<StoredInvoice>, StorageError> {
        let inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(inner.invoices.get(payment_hash).cloned())
    }

    fn get_invoice_for_status(&self, payment_hash: &str, status_token: &str) -> Result<Option<StoredInvoice>, StorageError> {
        let inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
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
        let inner = self.inner.lock().map_err(|e| StorageError::Database(e.to_string()))?;
        let count = inner
            .invoices
            .values()
            .filter(|inv| inv.client_ip.as_deref() == Some(client_ip))
            .count();
        Ok(count as u64)
    }

    fn prune_expired_invoices(&self, _max_age: std::time::Duration) -> Result<u64, StorageError> {
        Ok(0)
    }

    fn prune_stale_records(&self, _max_age: std::time::Duration) -> Result<u64, StorageError> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> String {
        format!("{:0>64}", n)
    }

    fn make_invoice(payment_hash: &str, status_token: &str, client_ip: Option<&str>) -> StoredInvoice {
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

        let settled = store.settle_with_credit(&h, 2000, Some(secret), Currency::Sat).unwrap();
        assert!(settled);
        assert_eq!(store.balance(&h, Currency::Sat).unwrap(), 2000);
        assert_eq!(store.get_settlement_secret(&h).unwrap(), Some(secret.to_string()));

        // Second settle should be rejected
        let settled_again = store.settle_with_credit(&h, 2000, Some(secret), Currency::Sat).unwrap();
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
        let retrieved = store.get_invoice(&h).unwrap().expect("invoice should exist");
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
        let wrong_token   = "wrong_status_token_xxxxxxxxxxxx_";
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
}
