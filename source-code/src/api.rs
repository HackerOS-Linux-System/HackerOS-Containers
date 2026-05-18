use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};
use tracing::{info, warn};

use crate::config::HkConfig;
use crate::container::HACKEROS_LOG;
use crate::db;
use crate::metrics::gather_metrics;
use crate::pod::PodSpec;
use crate::tls;
use crate::validation::{
    validate_cpu_percent, validate_env_var, validate_image_ref, validate_memory_limit,
    validate_mount, validate_name, validate_port_mapping,
};

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub api_token: Option<String>,
}

// ── Request DTOs ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateContainerRequest {
    pub name: String,
    pub image: String,
    pub mounts: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub memory_limit: Option<String>,
    pub cpu_percent: Option<u64>,
    pub auto_restart: Option<bool>,
    pub rootless: Option<bool>,
}

impl CreateContainerRequest {
    fn validate(&self) -> miette::Result<()> {
        validate_name(&self.name)?;
        validate_image_ref(&self.image)?;
        for m in self.mounts.iter().flatten() {
            validate_mount(m)?;
        }
        for p in self.ports.iter().flatten() {
            validate_port_mapping(p)?;
        }
        for e in self.env.iter().flatten() {
            validate_env_var(e)?;
        }
        if let Some(m) = &self.memory_limit {
            validate_memory_limit(m)?;
        }
        if let Some(c) = self.cpu_percent {
            validate_cpu_percent(c)?;
        }
        Ok(())
    }
}

impl From<CreateContainerRequest> for HkConfig {
    fn from(r: CreateContainerRequest) -> Self {
        HkConfig {
            metadata: crate::config::Metadata {
                name: r.name,
                version: "0.1".into(),
                authors: String::new(),
                license: String::new(),
            },
            specs: crate::config::Specs {
                base_image: r.image,
                memory_limit: r.memory_limit,
                cpu_percent: r.cpu_percent,
                mounts: r.mounts.unwrap_or_default(),
                port_mappings: r.ports.unwrap_or_default(),
                env: r.env.unwrap_or_default(),
                cmd: r.cmd.unwrap_or_default(),
            },
            runtime: crate::config::Runtime {
                auto_restart: r.auto_restart.unwrap_or(false),
                network_mode: "bridge".into(),
                cni_network: None,
            },
            security: crate::config::Security {
                rootless: r.rootless.unwrap_or(false),
                ..Default::default()
            },
            network: Default::default(),
        }
    }
}

// ── Response DTOs ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct CreateContainerResponse {
    id: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    containers_running: usize,
}

#[derive(Deserialize)]
pub struct PaginationParams {
    page: Option<usize>,
    per_page: Option<usize>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bad_request(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
     Json(ErrorResponse { error: msg.into() }),
    )
    .into_response()
}

fn not_found(msg: impl Into<String>) -> Response {
    (
        StatusCode::NOT_FOUND,
     Json(ErrorResponse { error: msg.into() }),
    )
    .into_response()
}

fn internal(msg: impl std::fmt::Display) -> Response {
    warn!("API error: {}", msg);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
     Json(ErrorResponse {
         error: msg.to_string(),
     }),
    )
    .into_response()
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.contains('/') && !id.contains('.')
}

// ── Auth middleware ───────────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
                         headers: HeaderMap,
                         request: axum::http::Request<axum::body::Body>,
                         next: Next,
) -> Response {
    if let Some(expected) = &state.api_token {
        let ok = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t == expected)
        .unwrap_or(false);
        if !ok {
            warn!("Unauthorized API request");
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Unauthorized".into(),
                }),
            )
            .into_response();
        }
    }
    next.run(request).await
}

// ── Router ────────────────────────────────────────────────────────────────────

pub async fn run_server(
    addr: String,
    api_token: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
) -> miette::Result<()> {
    let state = Arc::new(AppState { api_token });

    let protected = Router::new()
    .route(
        "/containers",
        get(list_containers).post(create_container),
    )
    .route("/containers/:id", delete(delete_container))
    .route("/containers/:id/start", post(start_container_handler))
    .route("/containers/:id/stop", post(stop_container_handler))
    .route("/containers/:id/logs", get(get_container_logs))
    .route("/pods", get(list_pods).post(create_pod))
    .route("/pods/:name", delete(delete_pod))
    .route("/pods/:name/start", post(start_pod_handler))
    .route("/pods/:name/stop", post(stop_pod_handler))
    .layer(middleware::from_fn_with_state(
        state.clone(),
                                          auth_middleware,
    ));

    let public = Router::new()
    .route("/health", get(health_handler))
    .route("/metrics", get(metrics_handler));

    let app = Router::new()
    .merge(protected)
    .merge(public)
    .layer(
        ServiceBuilder::new()
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(60))),
    )
    .with_state(state);

    if tls::tls_files_present(&tls_cert, &tls_key) {
        run_tls(addr, app, tls_cert.unwrap(), tls_key.unwrap()).await
    } else {
        if tls_cert.is_some() || tls_key.is_some() {
            warn!("TLS cert/key specified but files not found — falling back to plain HTTP");
        }
        run_plain(addr, app).await
    }
}

async fn run_plain(addr: String, app: Router) -> miette::Result<()> {
    let listener = TcpListener::bind(&addr)
    .await
    .map_err(|e| miette::miette!("Cannot bind {}: {}", addr, e))?;
    info!("API listening (plain HTTP) on {}", addr);
    println!("  API  http://{}", addr);
    axum::serve(listener, app)
    .await
    .map_err(|e| miette::miette!("Server error: {}", e))
}

async fn run_tls(
    addr: String,
    app: Router,
    cert: String,
    key: String,
) -> miette::Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    let tls_config = tls::build_server_config(&cert, &key)?;
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(&addr)
    .await
    .map_err(|e| miette::miette!("Cannot bind {}: {}", addr, e))?;

    info!("API listening (TLS/HTTPS) on {}", addr);
    println!("  API  https://{}", addr);

    // MakeService clones the app per connection
    let mut make_svc = app.into_make_service();

    loop {
        let (stream, peer_addr) = listener
        .accept()
        .await
        .map_err(|e| miette::miette!("Accept error: {}", e))?;

        let acceptor = acceptor.clone();

        // Produce a per-connection tower Service …
        let tower_svc = match make_svc.call(peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("make_service error from {}: {}", peer_addr, e);
                continue;
            }
        };

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    // … then wrap it so hyper 1.x gets hyper::service::Service
                    let hyper_svc = TowerToHyperService::new(tower_svc);
                    if let Err(e) =
                        http1::Builder::new().serve_connection(io, hyper_svc).await
                        {
                            warn!("TLS connection error from {}: {}", peer_addr, e);
                        }
                }
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer_addr, e)
                }
            }
        });
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health_handler(State(_s): State<Arc<AppState>>) -> Response {
    let running = db::count_running_containers();
    Json(HealthResponse {
        status: "ok",
         version: env!("CARGO_PKG_VERSION"),
         containers_running: running,
    })
    .into_response()
}

async fn list_containers(
    State(_s): State<Arc<AppState>>,
                         Query(p): Query<PaginationParams>,
) -> Response {
    let page = p.page.unwrap_or(1).max(1);
    let per_page = p.per_page.unwrap_or(50).clamp(1, 200);
    match tokio::task::spawn_blocking(move || db::list_containers_paged(page, per_page))
    .await
    {
        Ok(Ok((rows, total))) => Json(json!({
            "containers": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
        }))
        .into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn create_container(
    State(_s): State<Arc<AppState>>,
                          Json(req): Json<CreateContainerRequest>,
) -> Response {
    if let Err(e) = req.validate() {
        return bad_request(e.to_string());
    }

    let config: HkConfig = req.into();
    let name = config.metadata.name.clone();

    let result = tokio::time::timeout(
        Duration::from_secs(300),
                                      tokio::task::spawn_blocking(move || {
                                          crate::container::start_container(config, true)
                                      }),
    )
    .await;

    match result {
        Err(_) => bad_request("Container start timed out (300 s)"),
        Ok(Ok(Ok(()))) => {
            let id = tokio::task::spawn_blocking(move || {
                db::find_container(&name).ok().map(|r| r.id)
            })
            .await
            .unwrap_or(None);
            (
                StatusCode::CREATED,
             Json(CreateContainerResponse {
                 id: id.unwrap_or_else(|| "unknown".into()),
             }),
            )
            .into_response()
        }
        Ok(Ok(Err(e))) => internal(e),
        Ok(Err(e)) => internal(e),
    }
}

async fn delete_container(
    State(_s): State<Arc<AppState>>,
                          Path(id): Path<String>,
) -> Response {
    if !safe_id(&id) {
        return bad_request("Invalid container id");
    }
    match tokio::task::spawn_blocking(move || crate::container::stop_container(&id))
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => {
            let s = e.to_string();
            if s.contains("not found") {
                not_found(s)
            } else {
                internal(s)
            }
        }
        Err(e) => internal(e),
    }
}

async fn start_container_handler(
    State(_s): State<Arc<AppState>>,
                                 Path(id): Path<String>,
) -> Response {
    if !safe_id(&id) {
        return bad_request("Invalid container id");
    }
    match tokio::task::spawn_blocking(move || crate::container::restart_container(&id))
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => {
            let s = e.to_string();
            if s.contains("not found") {
                not_found(s)
            } else {
                internal(s)
            }
        }
        Err(e) => internal(e),
    }
}

async fn stop_container_handler(
    State(_s): State<Arc<AppState>>,
                                Path(id): Path<String>,
) -> Response {
    if !safe_id(&id) {
        return bad_request("Invalid container id");
    }
    match tokio::task::spawn_blocking(move || crate::container::stop_container(&id))
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn get_container_logs(
    State(_s): State<Arc<AppState>>,
                            Path(id): Path<String>,
) -> Response {
    if !safe_id(&id) {
        return bad_request("Invalid container id");
    }
    let cid = id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let log_path = std::path::PathBuf::from(HACKEROS_LOG)
        .join(format!("{}.log", cid));
        if log_path.exists() {
            std::fs::read_to_string(&log_path)
            .map_err(|e| miette::miette!("{}", e))
        } else {
            Ok(String::new())
        }
    })
    .await;
    match result {
        Ok(Ok(logs)) => {
            Json(json!({ "container_id": id, "logs": logs })).into_response()
        }
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn list_pods(
    State(_s): State<Arc<AppState>>,
                   Query(p): Query<PaginationParams>,
) -> Response {
    let page = p.page.unwrap_or(1).max(1);
    let per_page = p.per_page.unwrap_or(50).clamp(1, 200);
    match tokio::task::spawn_blocking(move || db::list_pods_paged(page, per_page)).await {
        Ok(Ok((rows, total))) => Json(json!({
            "pods": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
        }))
        .into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn create_pod(
    State(_s): State<Arc<AppState>>,
                    Json(spec): Json<PodSpec>,
) -> Response {
    if let Err(e) = validate_name(&spec.name) {
        return bad_request(e.to_string());
    }
    let result = tokio::time::timeout(
        Duration::from_secs(600),
                                      tokio::task::spawn_blocking(move || {
                                          let name = spec.name.clone();
                                          crate::pod::start_pod(&name, spec)
                                      }),
    )
    .await;
    match result {
        Err(_) => bad_request("Pod start timed out (600 s)"),
        Ok(Ok(Ok(()))) => StatusCode::CREATED.into_response(),
        Ok(Ok(Err(e))) => internal(e),
        Ok(Err(e)) => internal(e),
    }
}

async fn delete_pod(
    State(_s): State<Arc<AppState>>,
                    Path(name): Path<String>,
) -> Response {
    if let Err(e) = validate_name(&name) {
        return bad_request(e.to_string());
    }
    match tokio::task::spawn_blocking(move || crate::pod::stop_pod(&name)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn start_pod_handler(
    State(_s): State<Arc<AppState>>,
                           Path(name): Path<String>,
) -> Response {
    if let Err(e) = validate_name(&name) {
        return bad_request(e.to_string());
    }
    match tokio::task::spawn_blocking(move || crate::pod::restart_pod(&name)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn stop_pod_handler(
    State(_s): State<Arc<AppState>>,
                          Path(name): Path<String>,
) -> Response {
    if let Err(e) = validate_name(&name) {
        return bad_request(e.to_string());
    }
    match tokio::task::spawn_blocking(move || crate::pod::stop_pod(&name)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

async fn metrics_handler(State(_s): State<Arc<AppState>>) -> Response {
    let metrics = tokio::task::spawn_blocking(gather_metrics)
    .await
    .unwrap_or_default();
    (
        StatusCode::OK,
     [(
         axum::http::header::CONTENT_TYPE,
       "text/plain; version=0.0.4",
     )],
     metrics,
    )
    .into_response()
}
