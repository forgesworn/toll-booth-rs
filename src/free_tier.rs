use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;

/// Result of a free tier check operation.
#[derive(Debug, Clone)]
pub struct FreeTierResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Remaining quota for this IP (requests or credits)
    pub remaining: u64,
}

/// Trait for free tier quota management.
pub trait IFreeTier: Send + Sync {
    /// Check if a request is allowed and consume quota if permitted.
    /// Zero-cost requests (cost: 0) always pass without consuming budget.
    fn check(&self, ip: &str, cost: u64) -> FreeTierResult;

    /// Reset all tracked quotas and date.
    fn reset(&self);
}

/// Validates whether an IP or hash is plausible.
fn is_plausible_ip_or_hash(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
}

/// Entry for a single IP in request-count free tier.
#[derive(Debug, Clone)]
struct IpEntry {
    count: u64,
    #[allow(dead_code)]
    date: String,
}

/// Request-count based free tier: N requests per day per IP.
pub struct FreeTier {
    requests_per_day: u64,
    state: Mutex<(String, HashMap<String, IpEntry>)>,
}

impl FreeTier {
    /// Create a new request-count free tier with the specified daily limit.
    pub fn new(requests_per_day: u64) -> Self {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        FreeTier {
            requests_per_day,
            state: Mutex::new((today, HashMap::new())),
        }
    }
}

impl IFreeTier for FreeTier {
    fn check(&self, ip: &str, _cost: u64) -> FreeTierResult {
        // Validate IP
        if !is_plausible_ip_or_hash(ip) {
            return FreeTierResult {
                allowed: false,
                remaining: 0,
            };
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let mut state = self.state.lock().unwrap();

        // Check if date has changed; if so, reset all entries
        if state.0 != today {
            state.0 = today.clone();
            state.1.clear();
        }

        let map = &mut state.1;

        // Check if at max capacity
        if !map.contains_key(ip) && map.len() >= 100_000 {
            return FreeTierResult {
                allowed: false,
                remaining: 0,
            };
        }

        let entry = map.entry(ip.to_string()).or_insert_with(|| IpEntry {
            count: 0,
            date: today.clone(),
        });

        // If at limit, deny
        if entry.count >= self.requests_per_day {
            return FreeTierResult {
                allowed: false,
                remaining: 0,
            };
        }

        // Allow and increment
        entry.count += 1;
        let remaining = self.requests_per_day - entry.count;

        FreeTierResult {
            allowed: true,
            remaining,
        }
    }

    fn reset(&self) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let mut state = self.state.lock().unwrap();
        state.0 = today;
        state.1.clear();
    }
}

/// Entry for a single IP in credit-budget free tier.
#[derive(Debug, Clone)]
struct SpentEntry {
    amount: u64,
    #[allow(dead_code)]
    date: String,
}

/// Credit-budget based free tier: N sats/credits per day per IP.
pub struct CreditFreeTier {
    credits_per_day: u64,
    state: Mutex<(String, HashMap<String, SpentEntry>)>,
}

impl CreditFreeTier {
    /// Create a new credit-budget free tier with the specified daily limit (in sats/credits).
    pub fn new(credits_per_day: u64) -> Self {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        CreditFreeTier {
            credits_per_day,
            state: Mutex::new((today, HashMap::new())),
        }
    }
}

impl IFreeTier for CreditFreeTier {
    fn check(&self, ip: &str, cost: u64) -> FreeTierResult {
        // Validate IP
        if !is_plausible_ip_or_hash(ip) {
            return FreeTierResult {
                allowed: false,
                remaining: 0,
            };
        }

        // Zero-cost requests always pass
        if cost == 0 {
            let state = self.state.lock().unwrap();
            let spent = state.1.get(ip).map(|e| e.amount).unwrap_or(0);
            return FreeTierResult {
                allowed: true,
                remaining: self.credits_per_day.saturating_sub(spent),
            };
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let mut state = self.state.lock().unwrap();

        // Check if date has changed; if so, reset all entries
        if state.0 != today {
            state.0 = today.clone();
            state.1.clear();
        }

        let map = &mut state.1;

        // Check if at max capacity
        if !map.contains_key(ip) && map.len() >= 100_000 {
            return FreeTierResult {
                allowed: false,
                remaining: 0,
            };
        }

        let entry = map.entry(ip.to_string()).or_insert_with(|| SpentEntry {
            amount: 0,
            date: today.clone(),
        });

        let remaining_budget = self.credits_per_day.saturating_sub(entry.amount);

        // If cost exceeds remaining budget, deny
        if cost > remaining_budget {
            return FreeTierResult {
                allowed: false,
                remaining: remaining_budget,
            };
        }

        // Allow and consume budget
        entry.amount += cost;
        let new_remaining = self.credits_per_day - entry.amount;

        FreeTierResult {
            allowed: true,
            remaining: new_remaining,
        }
    }

    fn reset(&self) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let mut state = self.state.lock().unwrap();
        state.0 = today;
        state.1.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_free_tier_allows_up_to_limit() {
        let tier = FreeTier::new(3);

        // First three requests allowed
        assert_eq!(
            tier.check("192.168.1.1", 0).allowed,
            true,
            "1st request should be allowed"
        );
        assert_eq!(
            tier.check("192.168.1.1", 0).allowed,
            true,
            "2nd request should be allowed"
        );
        assert_eq!(
            tier.check("192.168.1.1", 0).allowed,
            true,
            "3rd request should be allowed"
        );

        // Fourth request denied
        assert_eq!(
            tier.check("192.168.1.1", 0).allowed,
            false,
            "4th request should be denied"
        );
    }

    #[test]
    fn request_free_tier_remaining() {
        let tier = FreeTier::new(5);

        let result1 = tier.check("10.0.0.1", 0);
        assert_eq!(
            result1.remaining, 4,
            "After 1 request, 4 remaining out of 5"
        );

        let result2 = tier.check("10.0.0.1", 0);
        assert_eq!(
            result2.remaining, 3,
            "After 2 requests, 3 remaining out of 5"
        );

        let result3 = tier.check("10.0.0.1", 0);
        assert_eq!(
            result3.remaining, 2,
            "After 3 requests, 2 remaining out of 5"
        );

        let result4 = tier.check("10.0.0.1", 0);
        assert_eq!(
            result4.remaining, 1,
            "After 4 requests, 1 remaining out of 5"
        );

        let result5 = tier.check("10.0.0.1", 0);
        assert_eq!(
            result5.remaining, 0,
            "After 5 requests, 0 remaining out of 5"
        );

        let result6 = tier.check("10.0.0.1", 0);
        assert_eq!(result6.allowed, false, "6th request should be denied");
        assert_eq!(result6.remaining, 0, "No remaining after limit hit");
    }

    #[test]
    fn request_free_tier_separate_ips() {
        let tier = FreeTier::new(2);

        // IP 1: use both slots
        assert_eq!(tier.check("192.168.1.1", 0).allowed, true);
        assert_eq!(tier.check("192.168.1.1", 0).allowed, true);
        assert_eq!(tier.check("192.168.1.1", 0).allowed, false);

        // IP 2: should have its own quota
        assert_eq!(tier.check("192.168.1.2", 0).allowed, true);
        assert_eq!(tier.check("192.168.1.2", 0).allowed, true);
        assert_eq!(tier.check("192.168.1.2", 0).allowed, false);

        // IP 3: separate again
        assert_eq!(tier.check("192.168.1.3", 0).allowed, true);
        assert_eq!(tier.check("192.168.1.3", 0).allowed, true);
        assert_eq!(tier.check("192.168.1.3", 0).allowed, false);
    }

    #[test]
    fn credit_free_tier_budget() {
        let tier = CreditFreeTier::new(1000);

        // Spend 400
        let result1 = tier.check("172.16.0.1", 400);
        assert_eq!(result1.allowed, true, "Should allow 400 sats");
        assert_eq!(
            result1.remaining, 600,
            "Should have 600 remaining after spending 400"
        );

        // Spend 600 (total 1000, at limit)
        let result2 = tier.check("172.16.0.1", 600);
        assert_eq!(
            result2.allowed, true,
            "Should allow 600 sats (reaches limit)"
        );
        assert_eq!(
            result2.remaining, 0,
            "Should have 0 remaining after spending 1000 total"
        );

        // Try to spend 1 more (over limit)
        let result3 = tier.check("172.16.0.1", 1);
        assert_eq!(
            result3.allowed, false,
            "Should deny 1 sat when budget exhausted"
        );
        assert_eq!(result3.remaining, 0, "Remaining should be 0");
    }

    #[test]
    fn credit_free_tier_zero_cost_passes() {
        let tier = CreditFreeTier::new(100);

        // Spend 100 to exhaust budget
        tier.check("203.0.113.1", 100);

        // Zero-cost should still pass even after budget exhausted
        let result = tier.check("203.0.113.1", 0);
        assert_eq!(result.allowed, true, "Zero-cost request should always pass");
        assert_eq!(result.remaining, 0, "Should report 0 remaining");

        // Multiple zero-cost calls should work
        assert_eq!(
            tier.check("203.0.113.1", 0).allowed,
            true,
            "Second zero-cost should pass"
        );
        assert_eq!(
            tier.check("203.0.113.1", 0).allowed,
            true,
            "Third zero-cost should pass"
        );
    }

    #[test]
    fn reset_clears_counters() {
        let tier = FreeTier::new(2);

        // Exhaust the quota
        tier.check("198.51.100.1", 0);
        tier.check("198.51.100.1", 0);
        assert_eq!(
            tier.check("198.51.100.1", 0).allowed,
            false,
            "Should be denied before reset"
        );

        // Reset
        tier.reset();

        // Should now be allowed again
        assert_eq!(
            tier.check("198.51.100.1", 0).allowed,
            true,
            "Should be allowed after reset"
        );
        assert_eq!(
            tier.check("198.51.100.1", 0).allowed,
            true,
            "Second request after reset should be allowed"
        );
        assert_eq!(
            tier.check("198.51.100.1", 0).allowed,
            false,
            "Third request should be denied again"
        );
    }

    #[test]
    fn implausible_ip_rejected() {
        let tier = FreeTier::new(10);

        // Empty string
        assert_eq!(
            tier.check("", 0).allowed,
            false,
            "Empty IP should be rejected"
        );

        // Too long (> 64 chars)
        let long_ip = "a".repeat(65);
        assert_eq!(
            tier.check(&long_ip, 0).allowed,
            false,
            "IP > 64 chars should be rejected"
        );

        // Invalid characters
        assert_eq!(
            tier.check("192.168.1.1@invalid", 0).allowed,
            false,
            "IP with @ should be rejected"
        );

        assert_eq!(
            tier.check("192.168.1.1 ", 0).allowed,
            false,
            "IP with space should be rejected"
        );

        // Valid IPs should be accepted
        assert_eq!(
            tier.check("192.168.1.1", 0).allowed,
            true,
            "Valid IPv4 should be accepted"
        );

        assert_eq!(
            tier.check("::1", 0).allowed,
            true,
            "Valid IPv6 should be accepted"
        );

        assert_eq!(
            tier.check("abcdef0123456789", 0).allowed,
            true,
            "Valid hex hash should be accepted"
        );
    }

    #[test]
    fn credit_free_tier_different_ips() {
        let tier = CreditFreeTier::new(1000);

        // IP 1: spend 500
        let r1 = tier.check("198.51.100.1", 500);
        assert_eq!(r1.allowed, true);
        assert_eq!(r1.remaining, 500);

        // IP 2: should have full budget
        let r2 = tier.check("198.51.100.2", 1000);
        assert_eq!(r2.allowed, true, "Different IP should have separate budget");
        assert_eq!(r2.remaining, 0);

        // IP 1 should still have 500 left
        let r3 = tier.check("198.51.100.1", 400);
        assert_eq!(r3.allowed, true);
        assert_eq!(r3.remaining, 100);

        // IP 2 should be exhausted
        let r4 = tier.check("198.51.100.2", 1);
        assert_eq!(r4.allowed, false);
    }
}
