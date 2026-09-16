//! Per-run rate-limiting, concurrency, and token budget enforcement (AG-41).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// A run's usage. Everything lives under one lock: a request is counted in the same critical
/// section that checks it, so two requests arriving together cannot both pass as the last one.
#[derive(Default)]
struct RunUsage {
    rpm_window: Option<Instant>,
    rpm_count: u32,
    tokens_consumed: u64,
    /// Model calls the run has made: one call is one step (AG-25, AG-51).
    steps: u32,
}

/// One minute, the window `requests_per_minute` is counted over.
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Default)]
pub struct LimitManager {
    runs: Arc<Mutex<HashMap<String, RunUsage>>>,
}

impl LimitManager {
    /// Counts one request of the run against its per-minute limit; refuses the one past it.
    pub async fn check_rpm(&self, run_id: &str, limit: u32) -> Result<(), &'static str> {
        self.check_rpm_at(run_id, limit, Instant::now()).await
    }

    async fn check_rpm_at(
        &self,
        run_id: &str,
        limit: u32,
        now: Instant,
    ) -> Result<(), &'static str> {
        let mut map = self.runs.lock().await;
        let entry = map.entry(run_id.to_string()).or_default();
        // ponytail: a fixed window that restarts a minute after its first request; a sliding
        // window is the upgrade if bursts at the boundary ever matter.
        match entry.rpm_window {
            Some(started) if now.duration_since(started) < WINDOW => {}
            _ => {
                entry.rpm_window = Some(now);
                entry.rpm_count = 0;
            }
        }
        if entry.rpm_count >= limit {
            return Err("rate limit exceeded (RPM limit)");
        }
        entry.rpm_count += 1;
        Ok(())
    }

    /// Counts one model call of the run against the profile's `stepsPerRun`; refuses the one past
    /// it, so a run that loops stops at the ceiling its profile declares (AG-25, AG-51). A limit of
    /// `0` counts nothing: a Portal that does not send the field yet bounds the run by tokens alone.
    pub async fn check_steps(&self, run_id: &str, limit: u32) -> Result<(), &'static str> {
        if limit == 0 {
            return Ok(());
        }
        // Counted in the same critical section that checks it, as the per-minute window is.
        let mut map = self.runs.lock().await;
        let entry = map.entry(run_id.to_string()).or_default();
        if entry.steps >= limit {
            return Err("step limit exceeded (stepsPerRun)");
        }
        entry.steps += 1;
        Ok(())
    }

    pub async fn check_tokens(&self, run_id: &str, limit: u64) -> Result<(), &'static str> {
        let map = self.runs.lock().await;
        let consumed = map.get(run_id).map_or(0, |entry| entry.tokens_consumed);
        if consumed >= limit {
            return Err("token budget exhausted");
        }
        Ok(())
    }

    pub async fn record_tokens(&self, run_id: &str, count: u64) {
        let mut map = self.runs.lock().await;
        map.entry(run_id.to_string()).or_default().tokens_consumed += count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_model_call_past_the_step_limit_is_refused_and_the_run_next_to_it_is_not() {
        let limits = LimitManager::default();
        for _ in 0..2 {
            assert_eq!(limits.check_steps("run-1", 2).await, Ok(()));
        }
        assert_eq!(
            limits.check_steps("run-1", 2).await,
            Err("step limit exceeded (stepsPerRun)")
        );
        assert_eq!(limits.check_steps("run-2", 2).await, Ok(()));
    }

    #[tokio::test]
    async fn a_profile_without_a_step_limit_counts_nothing() {
        let limits = LimitManager::default();
        for _ in 0..50 {
            assert_eq!(limits.check_steps("run-1", 0).await, Ok(()));
        }
        // The steps of the unbounded calls are not held against a limit that arrives later.
        assert_eq!(limits.check_steps("run-1", 1).await, Ok(()));
    }

    #[tokio::test]
    async fn the_request_past_the_limit_is_refused_and_the_window_restarts_after_a_minute() {
        let limits = LimitManager::default();
        let start = Instant::now();
        for _ in 0..3 {
            assert_eq!(limits.check_rpm_at("run-1", 3, start).await, Ok(()));
        }
        assert!(
            limits.check_rpm_at("run-1", 3, start).await.is_err(),
            "the fourth in the minute"
        );
        assert_eq!(
            limits.check_rpm_at("run-2", 3, start).await,
            Ok(()),
            "another run has its own count"
        );
        let later = start + WINDOW;
        assert_eq!(
            limits.check_rpm_at("run-1", 3, later).await,
            Ok(()),
            "a new minute, a new count"
        );
    }

    #[tokio::test]
    async fn tokens_are_summed_and_the_budget_refuses_once_reached() {
        let limits = LimitManager::default();
        assert_eq!(limits.check_tokens("run-1", 100).await, Ok(()));
        limits.record_tokens("run-1", 60).await;
        limits.record_tokens("run-1", 40).await;
        assert!(limits.check_tokens("run-1", 100).await.is_err());
        assert_eq!(limits.check_tokens("run-2", 100).await, Ok(()));
    }
}
