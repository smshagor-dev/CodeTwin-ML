//! Retries with jitter, a circuit breaker and a concurrency limiter.
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::error::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay_ms: 400,
            max_delay_ms: 8_000,
        }
    }
}

impl RetryPolicy {
    /// Exponential backoff with full jitter derived from the request id, so
    /// retries are spread out without a random-number dependency.
    pub fn delay(&self, request_id: &str, attempt: u32) -> Duration {
        let cap = self
            .base_delay_ms
            .saturating_mul(1u64 << attempt.min(16))
            .min(self.max_delay_ms)
            .max(1);
        let digest = Sha256::digest(format!("{request_id}:{attempt}").as_bytes());
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&digest[..8]);
        let jitter = u64::from_le_bytes(seed) % cap;
        Duration::from_millis(cap / 2 + jitter / 2)
    }
}

#[derive(Debug)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// Opens after `threshold` consecutive infrastructure failures and rejects
/// calls until `cooldown` elapses; one trial call then decides.
#[derive(Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    state: Mutex<BreakerState>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            threshold: threshold.max(1),
            cooldown,
            state: Mutex::new(BreakerState {
                consecutive_failures: 0,
                open_until: None,
            }),
        }
    }

    pub fn check(&self) -> Result<(), ProviderError> {
        let mut s = self.state.lock().expect("breaker mutex");
        match s.open_until {
            Some(until) if Instant::now() < until => Err(ProviderError::CircuitOpen),
            Some(_) => {
                s.open_until = None; // half-open: allow a trial call
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn record(&self, result: Result<(), &ProviderError>) {
        let mut s = self.state.lock().expect("breaker mutex");
        match result {
            Ok(()) => s.consecutive_failures = 0,
            Err(e) if e.trips_breaker() => {
                s.consecutive_failures += 1;
                if s.consecutive_failures >= self.threshold {
                    s.open_until = Some(Instant::now() + self.cooldown);
                    s.consecutive_failures = 0;
                }
            }
            Err(_) => {}
        }
    }

    pub fn is_open(&self) -> bool {
        self.state
            .lock()
            .expect("breaker mutex")
            .open_until
            .is_some_and(|u| Instant::now() < u)
    }
}

/// Bounded concurrent requests with a bounded wait.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    max: usize,
    active: Mutex<usize>,
    cv: Condvar,
}

pub struct Permit<'a>(&'a ConcurrencyLimiter);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.active.lock().expect("limiter mutex") -= 1;
        self.0.cv.notify_one();
    }
}

impl ConcurrencyLimiter {
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            active: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    pub fn acquire(&self, wait: Duration) -> Result<Permit<'_>, ProviderError> {
        let deadline = Instant::now() + wait;
        let mut active = self.active.lock().expect("limiter mutex");
        while *active >= self.max {
            let now = Instant::now();
            if now >= deadline {
                return Err(ProviderError::Saturated);
            }
            active = self
                .cv
                .wait_timeout(active, deadline - now)
                .expect("limiter mutex")
                .0;
        }
        *active += 1;
        Ok(Permit(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_deterministic() {
        let p = RetryPolicy {
            max_retries: 5,
            base_delay_ms: 100,
            max_delay_ms: 1_000,
        };
        for attempt in 0..10 {
            let d = p.delay("req", attempt);
            assert!(d <= Duration::from_millis(1_000));
            assert_eq!(d, p.delay("req", attempt));
        }
        assert_ne!(p.delay("a", 3), p.delay("b", 3));
    }

    #[test]
    fn breaker_opens_on_infrastructure_failures_only() {
        let b = CircuitBreaker::new(2, Duration::from_millis(50));
        b.record(Err(&ProviderError::Unauthorized("x".into())));
        b.record(Err(&ProviderError::Unauthorized("x".into())));
        assert!(b.check().is_ok(), "auth errors do not trip the breaker");
        b.record(Err(&ProviderError::Unavailable(503)));
        b.record(Err(&ProviderError::Unavailable(503)));
        assert_eq!(b.check(), Err(ProviderError::CircuitOpen));
        std::thread::sleep(Duration::from_millis(60));
        assert!(b.check().is_ok(), "half-open after cooldown");
    }

    #[test]
    fn limiter_bounds_concurrency() {
        let l = ConcurrencyLimiter::new(1);
        let p = l.acquire(Duration::from_millis(10)).unwrap();
        assert_eq!(
            l.acquire(Duration::from_millis(10)).err(),
            Some(ProviderError::Saturated)
        );
        drop(p);
        assert!(l.acquire(Duration::from_millis(10)).is_ok());
    }
}
