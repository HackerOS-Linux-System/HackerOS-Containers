use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use prometheus::{
    register_counter, register_gauge, register_gauge_vec, Counter, Encoder,
    Gauge, GaugeVec, TextEncoder,
};

use crate::container::CGROUP_ROOT;
use crate::db::ContainerRow;

// ── Prometheus metrics ────────────────────────────────────────────────────────

lazy_static! {
    pub static ref CONTAINERS_TOTAL: Gauge =
    register_gauge!("hco_containers_total", "Total containers ever created").unwrap();
    pub static ref CONTAINERS_RUNNING: Gauge =
    register_gauge!("hco_containers_running", "Currently running containers").unwrap();
    pub static ref CONTAINER_MEMORY_BYTES: GaugeVec = register_gauge_vec!(
        "hco_container_memory_bytes",
        "Memory usage in bytes",
        &["id", "name"]
    )
    .unwrap();
    pub static ref CONTAINER_CPU_PERCENT: GaugeVec = register_gauge_vec!(
        "hco_container_cpu_usage_percent",
        "CPU usage percent (1-second window)",
                                                                         &["id", "name"]
    )
    .unwrap();
    pub static ref CONTAINER_START_TOTAL: Counter =
    register_counter!("hco_container_start_total", "Total container starts").unwrap();
}

// ── CPU accounting ────────────────────────────────────────────────────────────

static PREV_CPU: Mutex<Option<HashMap<String, (u64, Instant)>>> =
Mutex::new(None);

fn read_cpu_usage_usec(cg_path: &PathBuf) -> Option<u64> {
    let content = fs::read_to_string(cg_path.join("cpu.stat")).ok()?;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("usage_usec ") {
            return val.trim().parse().ok();
        }
    }
    None
}

fn read_memory_bytes(cg_path: &PathBuf) -> u64 {
    fs::read_to_string(cg_path.join("memory.current"))
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0)
}

// ── Collection loop ───────────────────────────────────────────────────────────

pub fn spawn_metrics_collector() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            tokio::task::spawn_blocking(collect_metrics_tick).await.ok();
        }
    });
}

fn collect_metrics_tick() {
    let Ok((rows, _)) = crate::db::list_containers_paged(1, 1000) else {
        return;
    };

    let now = Instant::now();
    let mut guard = PREV_CPU.lock().unwrap();
    let prev_map = guard.get_or_insert_with(HashMap::new);
    let mut next_map: HashMap<String, (u64, Instant)> = HashMap::new();

    for row in &rows {
        if row.status != "Running" {
            continue;
        }
        let cg_path = PathBuf::from(format!("{}/{}", CGROUP_ROOT, row.id));

        let mem = read_memory_bytes(&cg_path);
        CONTAINER_MEMORY_BYTES
        .with_label_values(&[&row.id, &row.name])
        .set(mem as f64);

        if let Some(usage_usec) = read_cpu_usage_usec(&cg_path) {
            if let Some((prev_usec, prev_instant)) = prev_map.get(&row.id) {
                let delta_usage = usage_usec.saturating_sub(*prev_usec) as f64;
                let delta_wall =
                now.duration_since(*prev_instant).as_micros() as f64;
                if delta_wall > 0.0 {
                    let pct = (delta_usage / delta_wall) * 100.0;
                    CONTAINER_CPU_PERCENT
                    .with_label_values(&[&row.id, &row.name])
                    .set(pct.min(100.0 * num_cpus()));
                }
            }
            next_map.insert(row.id.clone(), (usage_usec, now));
        }
    }

    *prev_map = next_map;
}

fn num_cpus() -> f64 {
    fs::read_to_string("/sys/devices/system/cpu/online")
    .ok()
    .and_then(|s| {
        let parts: Vec<&str> = s.trim().split('-').collect();
        let lo: u64 = parts.first()?.parse().ok()?;
        let hi: u64 = parts.last()?.parse().ok()?;
        Some((hi - lo + 1) as f64)
    })
    .unwrap_or(1.0)
}

// ── Lifecycle hooks ───────────────────────────────────────────────────────────

pub fn record_container_started(row: &ContainerRow) {
    CONTAINERS_TOTAL.inc();
    CONTAINERS_RUNNING.inc();
    CONTAINER_START_TOTAL.inc();
    CONTAINER_MEMORY_BYTES
    .with_label_values(&[&row.id, &row.name])
    .set(0.0);
    CONTAINER_CPU_PERCENT
    .with_label_values(&[&row.id, &row.name])
    .set(0.0);
}

pub fn record_container_stopped(id: &str, name: &str) {
    CONTAINERS_RUNNING.dec();
    let _ = CONTAINER_MEMORY_BYTES.remove_label_values(&[id, name]);
    let _ = CONTAINER_CPU_PERCENT.remove_label_values(&[id, name]);
}

// ── Exposition ────────────────────────────────────────────────────────────────

pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let families = prometheus::gather();
    let mut buf = Vec::new();
    if encoder.encode(&families, &mut buf).is_err() {
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}
