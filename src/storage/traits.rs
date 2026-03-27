use crate::types::{Currency, DebitResult, StorageError, StoredInvoice};

pub trait StorageBackend: Send + Sync {
    fn credit(&self, payment_hash: &str, amount: i64, currency: Currency) -> Result<(), StorageError>;
    fn debit(&self, payment_hash: &str, amount: i64, currency: Currency) -> Result<DebitResult, StorageError>;
    fn balance(&self, payment_hash: &str, currency: Currency) -> Result<i64, StorageError>;
    fn adjust_credits(&self, payment_hash: &str, delta: i64, currency: Currency) -> Result<i64, StorageError>;

    fn settle(&self, payment_hash: &str) -> Result<bool, StorageError>;
    fn settle_with_credit(&self, payment_hash: &str, amount: i64, settlement_secret: Option<&str>, currency: Currency) -> Result<bool, StorageError>;
    fn is_settled(&self, payment_hash: &str) -> Result<bool, StorageError>;
    fn get_settlement_secret(&self, payment_hash: &str) -> Result<Option<String>, StorageError>;

    fn store_invoice(&self, invoice: &StoredInvoice) -> Result<(), StorageError>;
    fn get_invoice(&self, payment_hash: &str) -> Result<Option<StoredInvoice>, StorageError>;
    fn get_invoice_for_status(&self, payment_hash: &str, status_token: &str) -> Result<Option<StoredInvoice>, StorageError>;
    fn pending_invoice_count(&self, client_ip: &str) -> Result<u64, StorageError>;

    fn prune_expired_invoices(&self, max_age: std::time::Duration) -> Result<u64, StorageError>;
    fn prune_stale_records(&self, max_age: std::time::Duration) -> Result<u64, StorageError>;
}
