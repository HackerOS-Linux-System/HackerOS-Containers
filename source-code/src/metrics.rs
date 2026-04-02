use lazy_static::lazy_static;
use prometheus::{register_gauge, register_gauge_vec, register_counter, Counter, Gauge, GaugeVec, Encoder, TextEncoder};
use crate::container::ContainerState;

lazy_static! {
    pub static ref CONTAINERS_TOTAL: Gauge =
    register_gauge!("containers_total", "Total number of containers ever created").unwrap();
    pub static ref CONTAINERS_RUNNING: Gauge =
    register_gauge!("containers_running", "Number of currently running containers").unwrap();
    pub static ref CONTAINER_MEMORY_BYTES: GaugeVec =
    register_gauge_vec!("container_memory_bytes", "Memory usage in bytes", &["id", "name"]).unwrap();
    pub static ref CONTAINER_CPU_USAGE: GaugeVec =
    register_gauge_vec!("container_cpu_usage_percent", "CPU usage percentage", &["id", "name"]).unwrap();
    pub static ref CONTAINER_START_COUNTER: Counter =
    register_counter!("container_start_total", "Total number of container starts").unwrap();
}

pub fn record_container_metrics(state: &ContainerState, started: bool) {
    if started {
        CONTAINERS_TOTAL.inc();
        CONTAINERS_RUNNING.inc();
        CONTAINER_START_COUNTER.inc();
        CONTAINER_MEMORY_BYTES
        .with_label_values(&[&state.id, &state.name])
        .set(0.0);
        CONTAINER_CPU_USAGE
        .with_label_values(&[&state.id, &state.name])
        .set(0.0);
    } else {
        CONTAINERS_RUNNING.dec();
    }
}

pub fn update_container_memory(id: &str, name: &str, bytes: u64) {
    CONTAINER_MEMORY_BYTES
    .with_label_values(&[id, name])
    .set(bytes as f64);
}

pub fn update_container_cpu(id: &str, name: &str, percent: f64) {
    CONTAINER_CPU_USAGE
    .with_label_values(&[id, name])
    .set(percent);
}

pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
