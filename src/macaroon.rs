use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::types::{Currency, MacaroonError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MACAROON_KEY_GENERATOR: &[u8] = b"macaroons-key-generator";

const FIELD_EOS: u8 = 0x00;
const FIELD_LOCATION: u8 = 0x01;
const FIELD_IDENTIFIER: u8 = 0x02;
const FIELD_SIGNATURE: u8 = 0x06;

const L402_ID_LEN: usize = 66;
const L402_VERSION: u16 = 0;

const RESERVED_CAVEAT_KEYS: &[&str] = &[
    "payment_hash",
    "credit_balance",
    "currency",
    "route",
    "expires",
    "ip",
];

// ---------------------------------------------------------------------------
// Helpers: HMAC-SHA256, key derivation, varint, base64
// ---------------------------------------------------------------------------

/// HMAC-SHA256(key, data) -> 32 bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derive a macaroon root key the same way the JS `macaroon` v3 package does:
/// `HMAC-SHA256("macaroons-key-generator", rootKey)`.
fn derive_key(root_key: &[u8]) -> Vec<u8> {
    hmac_sha256(MACAROON_KEY_GENERATOR, root_key).to_vec()
}

/// Encode an unsigned 64-bit integer as LEB128 varint.
fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a LEB128 varint from the start of `data`.
/// Returns `(value, bytes_consumed)`.
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        let low7 = (byte & 0x7F) as u64;
        value |= low7.checked_shl(shift)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        if shift >= 70 {
            return None; // overflow guard
        }
    }
    None // ran out of bytes
}

/// URL-safe base64 encoding without padding.
pub fn base64_url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// URL-safe base64 decoding (no padding expected).
pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

// ---------------------------------------------------------------------------
// V2 binary field writing / reading
// ---------------------------------------------------------------------------

/// Write a single V2 field: `field_type | varint(length) | data`.
fn write_field(buf: &mut Vec<u8>, field_type: u8, data: &[u8]) {
    buf.push(field_type);
    encode_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

/// Read a single V2 field from `data[pos..]`.
/// Returns `(field_type, field_data, new_pos)`.
fn read_field(data: &[u8], pos: usize) -> Option<(u8, Vec<u8>, usize)> {
    if pos >= data.len() {
        return None;
    }
    let field_type = data[pos];
    if field_type == FIELD_EOS {
        return Some((FIELD_EOS, Vec::new(), pos + 1));
    }
    let (len, consumed) = decode_varint(&data[pos + 1..])?;
    let field_len: usize = usize::try_from(len).ok()?;
    let start = pos + 1 + consumed;
    let end = start.checked_add(field_len)?;
    if end > data.len() {
        return None;
    }
    Some((field_type, data[start..end].to_vec(), end))
}

// ---------------------------------------------------------------------------
// L402 Identifier (66 bytes)
// ---------------------------------------------------------------------------

/// Build a 66-byte L402 identifier:
/// - bytes 0..2: version (uint16 BE, always 0)
/// - bytes 2..34: payment hash (32 bytes from hex)
/// - bytes 34..66: random token ID (32 bytes)
pub fn encode_l402_identifier(payment_hash: &str) -> Result<Vec<u8>, MacaroonError> {
    let hash_bytes = hex::decode(payment_hash).map_err(|_| MacaroonError::InvalidPaymentHash)?;
    if hash_bytes.len() != 32 {
        return Err(MacaroonError::InvalidPaymentHash);
    }

    let mut id = Vec::with_capacity(L402_ID_LEN);
    id.extend_from_slice(&L402_VERSION.to_be_bytes()); // 2 bytes
    id.extend_from_slice(&hash_bytes); // 32 bytes
    let mut token_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_id);
    id.extend_from_slice(&token_id); // 32 bytes
    debug_assert_eq!(id.len(), L402_ID_LEN);
    Ok(id)
}

/// Extract the payment hash (hex) from a 66-byte L402 identifier.
/// Returns `None` if the identifier is too short or has the wrong version.
pub fn decode_l402_identifier(id: &[u8]) -> Option<String> {
    if id.len() < L402_ID_LEN {
        return None;
    }
    let version = u16::from_be_bytes([id[0], id[1]]);
    if version != L402_VERSION {
        return None;
    }
    Some(hex::encode(&id[2..34]))
}

// ---------------------------------------------------------------------------
// Internal Macaroon struct (pub(crate))
// ---------------------------------------------------------------------------

pub(crate) struct Macaroon {
    location: Option<String>,
    identifier: Vec<u8>,
    signature: [u8; 32],
    caveats: Vec<Vec<u8>>, // first-party caveat identifiers (bytes)
}

impl Macaroon {
    /// Create a new macaroon. Applies `derive_key` to the root key before use.
    pub(crate) fn create(root_key: &[u8], identifier: &[u8]) -> Self {
        let derived = derive_key(root_key);
        let sig = hmac_sha256(&derived, identifier);
        Macaroon {
            location: None,
            identifier: identifier.to_vec(),
            signature: sig,
            caveats: Vec::new(),
        }
    }

    /// Add a UTF-8 first-party caveat.
    pub(crate) fn add_first_party_caveat(&mut self, caveat: &str) {
        let caveat_bytes = caveat.as_bytes();
        self.signature = hmac_sha256(&self.signature, caveat_bytes);
        self.caveats.push(caveat_bytes.to_vec());
    }

    /// Serialise to V2 binary format.
    pub(crate) fn serialise_v2(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Version byte
        buf.push(2);

        // Optional location
        if let Some(ref loc) = self.location {
            write_field(&mut buf, FIELD_LOCATION, loc.as_bytes());
        }
        // Required identifier
        write_field(&mut buf, FIELD_IDENTIFIER, &self.identifier);
        // EOS for header section
        buf.push(FIELD_EOS);

        // Caveats
        for caveat_id in &self.caveats {
            write_field(&mut buf, FIELD_IDENTIFIER, caveat_id);
            buf.push(FIELD_EOS);
        }

        // Final EOS before signature
        buf.push(FIELD_EOS);

        // Signature
        write_field(&mut buf, FIELD_SIGNATURE, &self.signature);

        buf
    }

    /// Deserialise from V2 binary format.
    fn deserialise_v2(data: &[u8]) -> Result<Self, MacaroonError> {
        if data.is_empty() || data[0] != 2 {
            return Err(MacaroonError::Encoding("not a V2 macaroon".into()));
        }
        let mut pos = 1;
        let mut location: Option<String> = None;
        let mut identifier: Option<Vec<u8>> = None;

        // Read header fields until EOS
        loop {
            let (ft, fd, next) = read_field(data, pos)
                .ok_or_else(|| MacaroonError::Encoding("truncated header".into()))?;
            pos = next;
            match ft {
                FIELD_EOS => break,
                FIELD_LOCATION => {
                    location = Some(
                        String::from_utf8(fd)
                            .map_err(|e| MacaroonError::Encoding(e.to_string()))?,
                    );
                }
                FIELD_IDENTIFIER => {
                    identifier = Some(fd);
                }
                _ => {} // skip unknown fields
            }
        }

        let identifier =
            identifier.ok_or_else(|| MacaroonError::Encoding("missing identifier".into()))?;

        // Read caveat sections. Each caveat has fields until EOS.
        // After the last caveat, another EOS signals end-of-caveats.
        let mut caveats: Vec<Vec<u8>> = Vec::new();
        loop {
            // Peek: is this the final EOS (before signature)?
            let (ft, fd, next) = read_field(data, pos)
                .ok_or_else(|| MacaroonError::Encoding("truncated caveats".into()))?;
            pos = next;
            if ft == FIELD_EOS {
                // End of caveats section
                break;
            }
            // Must be FIELD_IDENTIFIER for a caveat
            if ft == FIELD_IDENTIFIER {
                let caveat_id = fd;
                // Read remaining caveat fields until EOS
                loop {
                    let (cft, _cfd, cnext) = read_field(data, pos)
                        .ok_or_else(|| MacaroonError::Encoding("truncated caveat".into()))?;
                    pos = cnext;
                    if cft == FIELD_EOS {
                        break;
                    }
                    // For first-party caveats we only care about the identifier;
                    // skip any other fields (e.g. vid, cl for third-party).
                }
                caveats.push(caveat_id);
            }
        }

        // Read signature field
        let (ft, fd, _next) = read_field(data, pos)
            .ok_or_else(|| MacaroonError::Encoding("truncated signature".into()))?;
        if ft != FIELD_SIGNATURE || fd.len() != 32 {
            return Err(MacaroonError::Encoding("bad signature field".into()));
        }
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&fd);

        Ok(Macaroon {
            location,
            identifier,
            signature: sig,
            caveats,
        })
    }

    /// Recompute the expected signature from root key + identifier + caveats.
    fn compute_expected_signature(&self, root_key: &[u8]) -> [u8; 32] {
        let derived = derive_key(root_key);
        let mut sig = hmac_sha256(&derived, &self.identifier);
        for caveat_id in &self.caveats {
            sig = hmac_sha256(&sig, caveat_id);
        }
        sig
    }
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

/// Match a route pattern against a request path.
///
/// If the pattern ends with `/*`, it matches any path starting with the prefix
/// (the part before `/*`). Otherwise, it requires an exact match.
pub fn match_route(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        path.starts_with(prefix)
            && (path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/')
    } else {
        pattern == path
    }
}

// ---------------------------------------------------------------------------
// Caveat parsing helper
// ---------------------------------------------------------------------------

/// Parse a `"key = value"` caveat string.
fn parse_caveat(caveat: &str) -> Option<(&str, &str)> {
    let mut parts = caveat.splitn(2, " = ");
    let key = parts.next()?.trim();
    let value = parts.next()?.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Map Currency to its lowercase string form.
fn currency_to_str(c: Currency) -> &'static str {
    match c {
        Currency::Sat => "sat",
        Currency::Usd => "usd",
    }
}

/// Parse a currency string.
fn currency_from_str(s: &str) -> Option<Currency> {
    match s {
        "sat" => Some(Currency::Sat),
        "usd" => Some(Currency::Usd),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Public API: VerifyContext / VerifyResult
// ---------------------------------------------------------------------------

pub struct VerifyContext<'a> {
    pub path: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub now: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct VerifyResult {
    pub valid: bool,
    pub payment_hash: Option<String>,
    pub credit_balance: Option<i64>,
    pub currency: Currency,
    pub custom_caveats: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Public API: mint, verify, parse
// ---------------------------------------------------------------------------

/// Mint a new L402 macaroon.
///
/// Adds mandatory caveats: `payment_hash`, `credit_balance`, `currency`.
/// Custom caveats must not use reserved keys.
/// Returns a URL-safe base64-encoded V2 macaroon.
pub fn mint_macaroon(
    root_key_hex: &str,
    payment_hash: &str,
    credit_balance: i64,
    custom_caveats: &[String],
    currency: Currency,
) -> Result<String, MacaroonError> {
    // Validate root key
    let root_key = hex::decode(root_key_hex).map_err(|_| MacaroonError::InvalidRootKey)?;
    if root_key.len() != 32 {
        return Err(MacaroonError::InvalidRootKey);
    }

    // Reject reserved keys in custom caveats
    for caveat in custom_caveats {
        if let Some((key, _)) = parse_caveat(caveat) {
            if RESERVED_CAVEAT_KEYS.contains(&key) {
                return Err(MacaroonError::InvalidCaveat(format!("reserved key: {key}")));
            }
        } else {
            return Err(MacaroonError::InvalidCaveat(format!(
                "malformed caveat: {caveat}"
            )));
        }
    }

    // Build identifier
    let id = encode_l402_identifier(payment_hash)?;

    // Create macaroon and add mandatory caveats
    let mut mac = Macaroon::create(&root_key, &id);
    mac.add_first_party_caveat(&format!("payment_hash = {payment_hash}"));
    mac.add_first_party_caveat(&format!("credit_balance = {credit_balance}"));
    mac.add_first_party_caveat(&format!("currency = {}", currency_to_str(currency)));

    // Add custom caveats
    for caveat in custom_caveats {
        mac.add_first_party_caveat(caveat);
    }

    // Serialise and encode
    let binary = mac.serialise_v2();
    Ok(base64_url_encode(&binary))
}

/// Verify a macaroon against a root key and optional context.
///
/// Returns a `VerifyResult` with `valid: false` rather than an error for
/// verification failures (wrong key, expired, route mismatch, etc.).
/// Returns `Err` only for structural decoding problems.
pub fn verify_macaroon(
    root_key_hex: &str,
    macaroon_b64: &str,
    context: Option<&VerifyContext>,
) -> Result<VerifyResult, MacaroonError> {
    let invalid = |currency| VerifyResult {
        valid: false,
        payment_hash: None,
        credit_balance: None,
        currency,
        custom_caveats: HashMap::new(),
    };

    // Decode root key
    let root_key = hex::decode(root_key_hex).map_err(|_| MacaroonError::InvalidRootKey)?;

    // Decode base64 -> binary -> parse V2
    let binary =
        base64_url_decode(macaroon_b64).map_err(|e| MacaroonError::Encoding(e.to_string()))?;
    let mac = Macaroon::deserialise_v2(&binary)?;

    // Verify HMAC signature
    let expected = mac.compute_expected_signature(&root_key);
    if expected.ct_eq(&mac.signature).unwrap_u8() != 1 {
        return Ok(invalid(Currency::default()));
    }

    // Parse all caveats, checking for duplicates
    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut all_caveats: HashMap<String, String> = HashMap::new();
    let mut custom_caveats: HashMap<String, String> = HashMap::new();

    for caveat_bytes in &mac.caveats {
        let caveat_str = std::str::from_utf8(caveat_bytes)
            .map_err(|e| MacaroonError::Encoding(e.to_string()))?;
        if let Some((key, value)) = parse_caveat(caveat_str) {
            if !seen_keys.insert(key.to_string()) {
                // Duplicate key -- reject
                return Ok(invalid(Currency::default()));
            }
            all_caveats.insert(key.to_string(), value.to_string());
            if !RESERVED_CAVEAT_KEYS.contains(&key) {
                custom_caveats.insert(key.to_string(), value.to_string());
            }
        }
    }

    // Extract payment hash from identifier and cross-check
    let id_payment_hash = decode_l402_identifier(&mac.identifier);
    let caveat_payment_hash = all_caveats.get("payment_hash").cloned();

    if let (Some(ref id_hash), Some(ref cav_hash)) = (&id_payment_hash, &caveat_payment_hash) {
        if id_hash != cav_hash {
            return Ok(invalid(Currency::default()));
        }
    }

    // Parse credit_balance
    let credit_balance = all_caveats
        .get("credit_balance")
        .and_then(|v| v.parse::<i64>().ok());

    // Parse currency
    let currency = all_caveats
        .get("currency")
        .and_then(|v| currency_from_str(v))
        .unwrap_or_default();

    // Context-based validation
    if let Some(ctx) = context {
        // Route check
        if let Some(route_pattern) = all_caveats.get("route") {
            if let Some(path) = ctx.path {
                if !match_route(route_pattern, path) {
                    return Ok(VerifyResult {
                        valid: false,
                        payment_hash: id_payment_hash,
                        credit_balance,
                        currency,
                        custom_caveats,
                    });
                }
            }
        }

        // Expires check
        if let Some(expires_str) = all_caveats.get("expires") {
            let now = ctx.now.unwrap_or_else(chrono::Utc::now);
            if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                if now >= expires_at {
                    return Ok(VerifyResult {
                        valid: false,
                        payment_hash: id_payment_hash,
                        credit_balance,
                        currency,
                        custom_caveats,
                    });
                }
            }
        }

        // IP check
        if let Some(allowed_ip) = all_caveats.get("ip") {
            if let Some(client_ip) = ctx.ip {
                if allowed_ip != client_ip {
                    return Ok(VerifyResult {
                        valid: false,
                        payment_hash: id_payment_hash,
                        credit_balance,
                        currency,
                        custom_caveats,
                    });
                }
            }
        }
    }

    Ok(VerifyResult {
        valid: true,
        payment_hash: id_payment_hash,
        credit_balance,
        currency,
        custom_caveats,
    })
}

/// Parse all caveats from a base64-encoded macaroon without verifying the signature.
/// Returns a map of `key -> value`.
/// Rejects macaroons with duplicate caveat keys.
pub fn parse_macaroon_caveats(
    macaroon_b64: &str,
) -> Result<HashMap<String, String>, MacaroonError> {
    let binary =
        base64_url_decode(macaroon_b64).map_err(|e| MacaroonError::Encoding(e.to_string()))?;
    let mac = Macaroon::deserialise_v2(&binary)?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut result: HashMap<String, String> = HashMap::new();

    for caveat_bytes in &mac.caveats {
        let caveat_str = std::str::from_utf8(caveat_bytes)
            .map_err(|e| MacaroonError::Encoding(e.to_string()))?;
        if let Some((key, value)) = parse_caveat(caveat_str) {
            if !seen.insert(key.to_string()) {
                return Err(MacaroonError::InvalidCaveat(format!(
                    "duplicate key: {key}"
                )));
            }
            result.insert(key.to_string(), value.to_string());
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROOT_KEY: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const TEST_PAYMENT_HASH: &str =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn derive_key_is_deterministic_and_different_from_input() {
        let key_bytes = hex::decode(TEST_ROOT_KEY).unwrap();
        let derived_a = derive_key(&key_bytes);
        let derived_b = derive_key(&key_bytes);
        assert_eq!(derived_a, derived_b, "derive_key must be deterministic");
        assert_ne!(
            derived_a.as_slice(),
            key_bytes.as_slice(),
            "derived key must differ from input"
        );
    }

    #[test]
    fn encode_decode_l402_identifier_roundtrip() {
        let id = encode_l402_identifier(TEST_PAYMENT_HASH).unwrap();
        assert_eq!(id.len(), 66, "L402 identifier must be 66 bytes");
        let decoded_hash = decode_l402_identifier(&id).unwrap();
        assert_eq!(decoded_hash, TEST_PAYMENT_HASH);
    }

    #[test]
    fn decode_rejects_short_identifier() {
        let short = vec![0u8; 10];
        assert!(decode_l402_identifier(&short).is_none());
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut id = encode_l402_identifier(TEST_PAYMENT_HASH).unwrap();
        id[0] = 0;
        id[1] = 1; // version 1 instead of 0
        assert!(decode_l402_identifier(&id).is_none());
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let mac_b64 =
            mint_macaroon(TEST_ROOT_KEY, TEST_PAYMENT_HASH, 1000, &[], Currency::Sat).unwrap();

        let result = verify_macaroon(TEST_ROOT_KEY, &mac_b64, None).unwrap();
        assert!(result.valid);
        assert_eq!(result.payment_hash.as_deref(), Some(TEST_PAYMENT_HASH));
        assert_eq!(result.credit_balance, Some(1000));
        assert_eq!(result.currency, Currency::Sat);
    }

    #[test]
    fn mint_with_custom_caveats_returned_on_verify() {
        let caveats = vec![
            "app_id = myapp123".to_string(),
            "tier = premium".to_string(),
        ];
        let mac_b64 = mint_macaroon(
            TEST_ROOT_KEY,
            TEST_PAYMENT_HASH,
            500,
            &caveats,
            Currency::Sat,
        )
        .unwrap();

        let result = verify_macaroon(TEST_ROOT_KEY, &mac_b64, None).unwrap();
        assert!(result.valid);
        assert_eq!(
            result.custom_caveats.get("app_id").map(|s| s.as_str()),
            Some("myapp123")
        );
        assert_eq!(
            result.custom_caveats.get("tier").map(|s| s.as_str()),
            Some("premium")
        );
    }

    #[test]
    fn verify_rejects_wrong_root_key() {
        let mac_b64 =
            mint_macaroon(TEST_ROOT_KEY, TEST_PAYMENT_HASH, 1000, &[], Currency::Sat).unwrap();

        let wrong_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result = verify_macaroon(wrong_key, &mac_b64, None).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn verify_rejects_duplicate_caveats() {
        // Attempt to mint with a reserved key -- should be rejected at mint time.
        let result = mint_macaroon(
            TEST_ROOT_KEY,
            TEST_PAYMENT_HASH,
            1000,
            &["payment_hash = evil".to_string()],
            Currency::Sat,
        );
        assert!(result.is_err(), "should reject reserved caveat key");

        // Also test the runtime duplicate-key detection during verification
        // by constructing a macaroon with a duplicate key manually.
        let root_key_bytes = hex::decode(TEST_ROOT_KEY).unwrap();
        let id = encode_l402_identifier(TEST_PAYMENT_HASH).unwrap();
        let mut mac = Macaroon::create(&root_key_bytes, &id);
        mac.add_first_party_caveat(
            "payment_hash = deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
        mac.add_first_party_caveat("credit_balance = 1000");
        mac.add_first_party_caveat("currency = sat");
        mac.add_first_party_caveat("credit_balance = 9999"); // duplicate!

        let binary = mac.serialise_v2();
        let mac_b64 = base64_url_encode(&binary);
        let result = verify_macaroon(TEST_ROOT_KEY, &mac_b64, None).unwrap();
        assert!(!result.valid, "duplicate caveat key must cause rejection");
    }

    #[test]
    fn verify_with_route_context_matching() {
        // Route is a reserved caveat key, so we construct directly via Macaroon API
        // (the server adds route caveats at mint time, not through custom_caveats).
        let root_key_bytes = hex::decode(TEST_ROOT_KEY).unwrap();
        let id = encode_l402_identifier(TEST_PAYMENT_HASH).unwrap();
        let mut mac = Macaroon::create(&root_key_bytes, &id);
        mac.add_first_party_caveat(&format!("payment_hash = {TEST_PAYMENT_HASH}"));
        mac.add_first_party_caveat("credit_balance = 1000");
        mac.add_first_party_caveat("currency = sat");
        mac.add_first_party_caveat("route = /api/*");

        let binary = mac.serialise_v2();
        let mac_b64 = base64_url_encode(&binary);

        let ctx_match = VerifyContext {
            path: Some("/api/foo/bar"),
            ip: None,
            now: None,
        };
        let result = verify_macaroon(TEST_ROOT_KEY, &mac_b64, Some(&ctx_match)).unwrap();
        assert!(result.valid);

        let ctx_no_match = VerifyContext {
            path: Some("/other/path"),
            ip: None,
            now: None,
        };
        let result2 = verify_macaroon(TEST_ROOT_KEY, &mac_b64, Some(&ctx_no_match)).unwrap();
        assert!(!result2.valid);
    }

    #[test]
    fn varint_roundtrip() {
        for &val in &[
            0u64,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            1_000_000,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let (decoded, _consumed) = decode_varint(&buf).expect("decode must succeed");
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
        }
    }

    #[test]
    fn match_route_wildcard_and_exact() {
        assert!(match_route("/api/*", "/api/foo"));
        assert!(match_route("/api/*", "/api/foo/bar"));
        assert!(!match_route("/api/*", "/other"));
        assert!(match_route("/exact", "/exact"));
        assert!(!match_route("/exact", "/exact/more"));
        assert!(!match_route("/exact", "/other"));
    }

    #[test]
    fn rejects_reserved_custom_caveat_key() {
        for reserved in &[
            "payment_hash",
            "credit_balance",
            "currency",
            "route",
            "expires",
            "ip",
        ] {
            let caveat = format!("{reserved} = test");
            let result = mint_macaroon(
                TEST_ROOT_KEY,
                TEST_PAYMENT_HASH,
                1000,
                &[caveat],
                Currency::Sat,
            );
            assert!(result.is_err(), "should reject reserved key: {reserved}");
        }
    }

    #[test]
    fn usd_currency_support() {
        let mac_b64 =
            mint_macaroon(TEST_ROOT_KEY, TEST_PAYMENT_HASH, 2500, &[], Currency::Usd).unwrap();

        let result = verify_macaroon(TEST_ROOT_KEY, &mac_b64, None).unwrap();
        assert!(result.valid);
        assert_eq!(result.credit_balance, Some(2500));
        assert_eq!(result.currency, Currency::Usd);
    }

    #[test]
    fn base64_url_roundtrip() {
        let data = b"hello macaroon world\x00\xff";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn parse_macaroon_caveats_returns_all_caveats() {
        let caveats = vec!["app_id = test123".to_string()];
        let mac_b64 = mint_macaroon(
            TEST_ROOT_KEY,
            TEST_PAYMENT_HASH,
            750,
            &caveats,
            Currency::Sat,
        )
        .unwrap();

        let parsed = parse_macaroon_caveats(&mac_b64).unwrap();
        assert_eq!(
            parsed.get("payment_hash").map(|s| s.as_str()),
            Some(TEST_PAYMENT_HASH)
        );
        assert_eq!(
            parsed.get("credit_balance").map(|s| s.as_str()),
            Some("750")
        );
        assert_eq!(parsed.get("currency").map(|s| s.as_str()), Some("sat"));
        assert_eq!(parsed.get("app_id").map(|s| s.as_str()), Some("test123"));
    }

    #[test]
    fn verify_expires_context() {
        use chrono::{TimeZone, Utc};

        let root_key_bytes = hex::decode(TEST_ROOT_KEY).unwrap();
        let id = encode_l402_identifier(TEST_PAYMENT_HASH).unwrap();
        let mut mac = Macaroon::create(&root_key_bytes, &id);
        mac.add_first_party_caveat(
            "payment_hash = deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
        mac.add_first_party_caveat("credit_balance = 1000");
        mac.add_first_party_caveat("currency = sat");
        mac.add_first_party_caveat("expires = 2099-01-01T00:00:00Z");

        let serialised = mac.serialise_v2();
        let mac_b64 = base64_url_encode(&serialised);

        // Before expiry -- should pass
        let ctx_before = VerifyContext {
            path: None,
            ip: None,
            now: Some(Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap()),
        };
        let result = verify_macaroon(TEST_ROOT_KEY, &mac_b64, Some(&ctx_before)).unwrap();
        assert!(result.valid, "should be valid before expiry");

        // After expiry -- should fail
        let ctx_after = VerifyContext {
            path: None,
            ip: None,
            now: Some(Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap()),
        };
        let result2 = verify_macaroon(TEST_ROOT_KEY, &mac_b64, Some(&ctx_after)).unwrap();
        assert!(!result2.valid, "should be invalid after expiry");
    }

    // -- Security: crafted macaroon binary robustness --

    #[test]
    fn read_field_rejects_oversized_varint_length() {
        // Craft a V2 macaroon binary with a field whose varint-encoded length
        // claims to be larger than the remaining buffer. This must not panic.
        let mut buf = vec![2u8]; // V2 version byte
        buf.push(FIELD_IDENTIFIER); // field type
                                    // Encode a varint for a very large length (e.g. u64::MAX)
        encode_varint(u64::MAX, &mut buf);
        // Provide only 4 bytes of actual data (far less than claimed)
        buf.extend_from_slice(b"tiny");
        buf.push(FIELD_EOS);

        let result = Macaroon::deserialise_v2(&buf);
        assert!(
            result.is_err(),
            "must reject macaroon with oversized field length"
        );
    }

    #[test]
    fn deserialise_rejects_truncated_binary() {
        // Empty after version byte
        let result = Macaroon::deserialise_v2(&[2u8]);
        assert!(
            result.is_err(),
            "must reject truncated macaroon (version only)"
        );

        // Just the version byte and a non-EOS field type, no length
        let result2 = Macaroon::deserialise_v2(&[2u8, FIELD_IDENTIFIER]);
        assert!(
            result2.is_err(),
            "must reject truncated macaroon (no field length)"
        );
    }

    #[test]
    fn decode_varint_rejects_overlong_encoding() {
        // 11 continuation bytes (would imply > 70-bit shift)
        let data = [0x80u8; 11];
        assert!(
            decode_varint(&data).is_none(),
            "must reject varint with > 10 continuation bytes"
        );
    }
}
