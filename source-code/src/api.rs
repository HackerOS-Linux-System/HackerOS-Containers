use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use miette::Result;

use crate::container::{self, ContainerState, HACKEROS_RUN, HACKEROS_LOG};
use crate::config::HkConfig;
use crate::pod::{PodSpec, PodState};
use crate::metrics::gather_metrics;

struct AppState;

#[derive(Deserialize)]
struct CreateContainerRequest {
    name: String,
    image: String,
    mounts: Option<Vec<String>>,
    ports: Option<Vec<String>>,
    env: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    memory_limit: Option<String>,
    cpu_percent: Option<u64>,
    auto_restart: Option<bool>,
    rootless: Option<bool>,
}

impl From<CreateContainerRequest> for HkConfig {
    fn from(req: CreateContainerRequest) -> Self {
        HkConfig {
            metadata: crate::config::Metadata {
                name: req.name,
                version: "0.1".to_string(),
                authors: "".to_string(),
                license: "".to_string(),
            },
            specs: crate::config::Specs {
                base_image: req.image,
                memory_limit: req.memory_limit,
                cpu_percent: req.cpu_percent,
                mounts: req.mounts.unwrap_or_default(),
                port_mappings: req.ports.unwrap_or_default(),
                env: req.env.unwrap_or_default(),
                cmd: req.cmd.unwrap_or_default(),
            },
            runtime: crate::config::Runtime {
                auto_restart: req.auto_restart.unwrap_or(false),
                network_mode: "bridge".to_string(),
                cni_network: None,
            },
            security: crate::config::Security {
                rootless: req.rootless.unwrap_or(false),
                ..Default::default()
            },
            network: Default::default(),
        }
    }
}

#[derive(Serialize)]
struct CreateContainerResponse {
    id: String,
}

#[derive(Serialize)]
struct ContainerListResponse {
    containers: Vec<ContainerState>,
}

#[derive(Serialize)]
struct LogResponse {
    logs: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn handle_error<E: std::fmt::Display>(err: E) -> Response {
    let body = ErrorResponse {
        error: err.to_string(),
    };
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

pub async fn run_server(addr: String) -> Result<()> {
    let state = Arc::new(AppState);
    let app = Router::new()
    .route("/containers", get(list_containers))
    .route("/containers", post(create_container))
    .route("/containers/:id", delete(delete_container))
    .route("/containers/:id/start", post(start_container_handler))
    .route("/containers/:id/stop", post(stop_container_handler))
    .route("/containers/:id/logs", get(get_container_logs))
    .route("/pods", get(list_pods))
    .route("/pods", post(create_pod))
    .route("/pods/:name", delete(delete_pod))
    .route("/pods/:name/start", post(start_pod_handler))
    .route("/pods/:name/stop", post(stop_pod_handler))
    .route("/metrics", get(metrics_handler))
    .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
    .await
    .map_err(|e| miette::miette!("Failed to bind to {}: {}", addr, e))?;
    println!("API server listening on {}", addr);
    axum::serve(listener, app)
    .await
    .map_err(|e| miette::miette!("Server error: {}", e))?;
    Ok(())
}

async fn list_containers(State(_state): State<Arc<AppState>>) -> Response {
    let containers = tokio::task::spawn_blocking(|| {
        let mut containers = Vec::new();
        if let Ok(entries) = std::fs::read_dir(HACKEROS_RUN) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "json") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(state) = serde_json::from_str::<ContainerState>(&content) {
                            containers.push(state);
                        }
                    }
                }
            }
        }
        containers
    })
    .await
    .unwrap_or_default();

    Json(ContainerListResponse { containers }).into_response()
}

async fn create_container(
    State(_state): State<Arc<AppState>>,
                          Json(req): Json<CreateContainerRequest>,
) -> Response {
    let config: HkConfig = req.into();
    let name = config.metadata.name.clone();

    let result = tokio::task::spawn_blocking(move || crate::container::start_container(config, true)).await;

    match result {
        Ok(Ok(())) => {
            let id = tokio::task::spawn_blocking(move || {
                let (_, state) = crate::container::find_container(&name).ok()?;
                Some(state.id)
            })
            .await
            .unwrap_or(None);
            match id {
                Some(id) => (StatusCode::CREATED, Json(CreateContainerResponse { id })).into_response(),
                None => (StatusCode::CREATED, Json(CreateContainerResponse { id: "unknown".into() })).into_response(),
            }
        }
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn delete_container(State(_state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || crate::container::stop_container(&id)).await;

    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn start_container_handler(State(_state): State<Arc<AppState>>, Path(_id): Path<String>) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
     Json(json!({"error": "Starting stopped containers not yet implemented"})),
    )
    .into_response()
}

async fn stop_container_handler(State(_state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || crate::container::stop_container(&id)).await;

    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn get_container_logs(State(_state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let log_path = std::path::PathBuf::from(HACKEROS_LOG).join(format!("{}.log", id));
        if log_path.exists() {
            std::fs::read_to_string(&log_path).map_err(|e| miette::miette!("Failed to read log: {}", e))
        } else {
            Ok(String::new())
        }
    })
    .await;

    match result {
        Ok(Ok(logs)) => Json(LogResponse { logs }).into_response(),
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn list_pods(State(_state): State<Arc<AppState>>) -> Response {
    let pods = tokio::task::spawn_blocking(|| {
        let mut pods = Vec::new();
        let pods_dir = std::path::PathBuf::from(crate::container::HACKEROS_RUN).join("pods");
        if pods_dir.exists() {
            for entry in std::fs::read_dir(pods_dir).unwrap_or_default().flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "json") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(state) = serde_json::from_str::<PodState>(&content) {
                            pods.push(state);
                        }
                    }
                }
            }
        }
        pods
    })
    .await
    .unwrap_or_default();

    Json(pods).into_response()
}

async fn create_pod(State(_state): State<Arc<AppState>>, Json(spec): Json<PodSpec>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let name = spec.name.clone();
        crate::pod::start_pod(&name, spec)
    }).await;

    match result {
        Ok(Ok(())) => StatusCode::CREATED.into_response(),
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn delete_pod(State(_state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || crate::pod::stop_pod(&name)).await;

    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn start_pod_handler(State(_state): State<Arc<AppState>>, Path(_name): Path<String>) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
     Json(json!({"error": "Starting pods not yet implemented"})),
    )
    .into_response()
}

async fn stop_pod_handler(State(_state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || crate::pod::stop_pod(&name)).await;

    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => handle_error(e).await,
        Err(e) => handle_error(e).await,
    }
}

async fn metrics_handler(State(_state): State<Arc<AppState>>) -> Response {
    let metrics = tokio::task::spawn_blocking(gather_metrics)
    .await
    .unwrap_or_else(|_| String::new());

    (StatusCode::OK, metrics).into_response()
}
