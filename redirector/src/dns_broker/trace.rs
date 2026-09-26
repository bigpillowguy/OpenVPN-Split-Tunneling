//! Bounded diagnostics contain transport metadata, never query names or RDATA.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(10);
const PER_WINDOW: u32 = 32;

#[derive(Clone, Copy)]
pub enum Category {
    Query,
    Outcome,
    Failure,
    Injection,
    Ownership,
}

struct Budget {
    since: Instant,
    counts: [u32; 5],
}
impl Budget {
    fn allow(&mut self, category: Category, now: Instant) -> bool {
        if now.duration_since(self.since) >= WINDOW {
            self.since = now;
            self.counts = [0; 5];
        }
        let count = &mut self.counts[category as usize];
        if *count >= PER_WINDOW {
            return false;
        }
        *count += 1;
        true
    }
}

pub fn allow(category: Category) -> bool {
    static BUDGET: LazyLock<Mutex<Budget>> = LazyLock::new(|| {
        Mutex::new(Budget {
            since: Instant::now(),
            counts: [0; 5],
        })
    });
    BUDGET
        .lock()
        .is_ok_and(|mut budget| budget.allow(category, Instant::now()))
}

#[derive(Clone, Copy)]
pub struct QueryTrace {
    pub serial: u64,
    pub pid: u32,
    pub qtype: u16,
}

impl QueryTrace {
    pub fn new(pid: u32, qtype: u16) -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(1);
        Self {
            serial: SERIAL.fetch_add(1, Ordering::Relaxed),
            pid,
            qtype,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_are_bounded_and_failures_keep_their_own_budget() {
        let start = Instant::now();
        let mut budget = Budget {
            since: start,
            counts: [0; 5],
        };
        for _ in 0..PER_WINDOW {
            assert!(budget.allow(Category::Outcome, start));
        }
        assert!(!budget.allow(Category::Outcome, start));
        assert!(budget.allow(Category::Failure, start));
        assert!(budget.allow(Category::Outcome, start + WINDOW));
        assert!(budget.allow(Category::Injection, start + WINDOW));
    }
}
