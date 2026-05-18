use chrono::{DateTime, Utc};
use miette::{miette, IntoDiagnostic, Result};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::config::HkConfig;

const SCHEMA_VERSION: i64 = 1;

static DB: OnceCell<Mutex<Connection>> = OnceCell::new();

// ── Init ──────────────────────────────────────────────────────────────────────

pub fn init_db(path: &str) -> Result<()> {
    let conn = Connection::open(path)
    .into_diagnostic()
    .map_err(|e| miette!("Cannot open state DB at {}: {}", path, e))?;

    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
    .into_diagnostic()?;

    run_migrations(&conn)?;

    DB.set(Mutex::new(conn))
    .map_err(|_| miette!("StateDb already initialised"))?;
    Ok(())
}

fn db() -> &'static Mutex<Connection> {
    DB.get().expect("StateDb not initialised — call init_db() first")
}

fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);",
    )
    .into_diagnostic()?;

    let version: i64 = conn
    .query_row(
        "SELECT version FROM schema_version LIMIT 1",
        [],
        |r| r.get(0),
    )
    .unwrap_or(0);

    if version < SCHEMA_VERSION {
        conn.execute_batch(include_str!("schema.sql"))
        .into_diagnostic()?;
        conn.execute(
            "DELETE FROM schema_version; INSERT INTO schema_version VALUES (?1)",
                     params![SCHEMA_VERSION],
        )
        .into_diagnostic()?;
        tracing::info!("DB schema migrated to v{}", SCHEMA_VERSION);
    }
    Ok(())
}

// ── Container row ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRow {
    pub id: String,
    pub name: String,
    pub image: String,
    pub pid: i32,
    pub status: String,
    pub ip_address: Option<String>,
    pub veth_host: Option<String>,
    pub bundle_path: String,
    pub ports_json: String,
    pub pod_id: Option<String>,
    pub auto_restart: bool,
    pub config_json: String,
    pub created_at: DateTime<Utc>,
}

impl ContainerRow {
    pub fn ports(&self) -> Vec<String> {
        serde_json::from_str(&self.ports_json).unwrap_or_default()
    }

    pub fn config(&self) -> Option<HkConfig> {
        serde_json::from_str(&self.config_json).ok()
    }
}

// ── Container CRUD ────────────────────────────────────────────────────────────

pub fn insert_container(row: &ContainerRow) -> Result<()> {
    let conn = db().lock();
    conn.execute(
        "INSERT INTO containers
        (id, name, image, pid, status, ip_address, veth_host,
                 bundle_path, ports_json, pod_id, auto_restart, config_json, created_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                 params![
                     row.id, row.name, row.image, row.pid, row.status,
                 row.ip_address, row.veth_host, row.bundle_path,
                 row.ports_json, row.pod_id, row.auto_restart as i32,
                 row.config_json, row.created_at.to_rfc3339(),
                 ],
    )
    .into_diagnostic()?;
    Ok(())
}

pub fn update_container_status(id: &str, status: &str) -> Result<()> {
    let conn = db().lock();
    conn.execute(
        "UPDATE containers SET status=?1 WHERE id=?2",
        params![status, id],
    )
    .into_diagnostic()?;
    Ok(())
}

pub fn delete_container(id: &str) -> Result<()> {
    let conn = db().lock();
    conn.execute("DELETE FROM containers WHERE id=?1", params![id])
    .into_diagnostic()?;
    Ok(())
}

pub fn find_container(prefix: &str) -> Result<ContainerRow> {
    let conn = db().lock();
    let pattern = format!("{}%", prefix);
    conn.query_row(
        "SELECT id,name,image,pid,status,ip_address,veth_host,
        bundle_path,ports_json,pod_id,auto_restart,config_json,created_at
        FROM containers
        WHERE id LIKE ?1 OR name=?1
        LIMIT 1",
        params![pattern],
        row_to_container,
    )
    .map_err(|e| miette!("Container '{}' not found: {}", prefix, e))
}

pub fn list_containers_paged(
    page: usize,
    per_page: usize,
) -> Result<(Vec<ContainerRow>, usize)> {
    let conn = db().lock();
    let total: usize = conn
    .query_row("SELECT COUNT(*) FROM containers", [], |r| r.get(0))
    .into_diagnostic()?;
    let offset = page.saturating_sub(1) * per_page;

    // Fix E0597: prepare + query_map + collect must all happen while conn is
    // still held. We collect into a Vec<_> before the MutexGuard is dropped.
    let mut stmt = conn
    .prepare(
        "SELECT id,name,image,pid,status,ip_address,veth_host,
        bundle_path,ports_json,pod_id,auto_restart,config_json,created_at
        FROM containers LIMIT ?1 OFFSET ?2",
    )
    .into_diagnostic()?;

    let rows: Vec<ContainerRow> = stmt
    .query_map(params![per_page as i64, offset as i64], row_to_container)
    .into_diagnostic()?
    .filter_map(|r| r.ok())
    .collect();

    Ok((rows, total))
}

pub fn count_running_containers() -> usize {
    let conn = db().lock();
    conn.query_row(
        "SELECT COUNT(*) FROM containers WHERE status='Running'",
                   [],
                   |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0) as usize
}

fn row_to_container(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContainerRow> {
    let created_str: String = r.get(12)?;
    let created_at = DateTime::parse_from_rfc3339(&created_str)
    .map(|d| d.with_timezone(&Utc))
    .unwrap_or_else(|_| Utc::now());
    Ok(ContainerRow {
        id:           r.get(0)?,
       name:         r.get(1)?,
       image:        r.get(2)?,
       pid:          r.get(3)?,
       status:       r.get(4)?,
       ip_address:   r.get(5)?,
       veth_host:    r.get(6)?,
       bundle_path:  r.get(7)?,
       ports_json:   r.get(8)?,
       pod_id:       r.get(9)?,
       auto_restart: r.get::<_, i32>(10)? != 0,
       config_json:  r.get(11)?,
       created_at,
    })
}

// ── Pod row ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodRow {
    pub name: String,
    pub container_ids_json: String,
    pub status: String,
    pub shared_network: bool,
    pub shared_pid: bool,
    pub shared_ipc: bool,
    pub netns_path: Option<String>,
    pub spec_json: String,
    pub created_at: DateTime<Utc>,
}

impl PodRow {
    pub fn container_ids(&self) -> Vec<String> {
        serde_json::from_str(&self.container_ids_json).unwrap_or_default()
    }
}

pub fn insert_pod(row: &PodRow) -> Result<()> {
    let conn = db().lock();
    conn.execute(
        "INSERT INTO pods
        (name, container_ids_json, status, shared_network, shared_pid,
                 shared_ipc, netns_path, spec_json, created_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                 params![
                     row.name, row.container_ids_json, row.status,
                 row.shared_network as i32, row.shared_pid as i32,
                 row.shared_ipc as i32, row.netns_path, row.spec_json,
                 row.created_at.to_rfc3339(),
                 ],
    )
    .into_diagnostic()?;
    Ok(())
}

pub fn delete_pod(name: &str) -> Result<()> {
    let conn = db().lock();
    conn.execute("DELETE FROM pods WHERE name=?1", params![name])
    .into_diagnostic()?;
    Ok(())
}

pub fn find_pod(name: &str) -> Result<PodRow> {
    let conn = db().lock();
    conn.query_row(
        "SELECT name,container_ids_json,status,shared_network,shared_pid,
        shared_ipc,netns_path,spec_json,created_at
        FROM pods WHERE name=?1",
        params![name],
        row_to_pod,
    )
    .map_err(|e| miette!("Pod '{}' not found: {}", name, e))
}

pub fn list_pods_paged(page: usize, per_page: usize) -> Result<(Vec<PodRow>, usize)> {
    let conn = db().lock();
    let total: usize = conn
    .query_row("SELECT COUNT(*) FROM pods", [], |r| r.get(0))
    .into_diagnostic()?;
    let offset = page.saturating_sub(1) * per_page;

    let mut stmt = conn
    .prepare(
        "SELECT name,container_ids_json,status,shared_network,shared_pid,
        shared_ipc,netns_path,spec_json,created_at
        FROM pods LIMIT ?1 OFFSET ?2",
    )
    .into_diagnostic()?;

    let rows: Vec<PodRow> = stmt
    .query_map(params![per_page as i64, offset as i64], row_to_pod)
    .into_diagnostic()?
    .filter_map(|r| r.ok())
    .collect();

    Ok((rows, total))
}

fn row_to_pod(r: &rusqlite::Row<'_>) -> rusqlite::Result<PodRow> {
    let created_str: String = r.get(8)?;
    let created_at = DateTime::parse_from_rfc3339(&created_str)
    .map(|d| d.with_timezone(&Utc))
    .unwrap_or_else(|_| Utc::now());
    Ok(PodRow {
        name:                 r.get(0)?,
       container_ids_json:   r.get(1)?,
       status:               r.get(2)?,
       shared_network:       r.get::<_, i32>(3)? != 0,
       shared_pid:           r.get::<_, i32>(4)? != 0,
       shared_ipc:           r.get::<_, i32>(5)? != 0,
       netns_path:           r.get(6)?,
       spec_json:            r.get(7)?,
       created_at,
    })
}

// ── IPAM ──────────────────────────────────────────────────────────────────────

pub fn ipam_allocate(container_id: &str, subnet_prefix: &str) -> Result<String> {
    let conn = db().lock();

    // Fix E0597: collect used suffixes before dropping the statement borrow
    let used: Vec<i64> = {
        let mut stmt = conn
        .prepare("SELECT suffix FROM ipam WHERE released=0")
        .into_diagnostic()?;
        let collected: Vec<i64> = stmt
        .query_map([], |r| r.get(0))
        .into_diagnostic()?
        .filter_map(|r| r.ok())
        .collect();
        collected
        // stmt dropped here — borrow ends before `conn` is used again below
    };

    let suffix = (2i64..=254)
    .find(|s| !used.contains(s))
    .ok_or_else(|| miette!("IPAM pool exhausted — no free IPs in /24"))?;

    conn.execute(
        "INSERT OR REPLACE INTO ipam (container_id, suffix, subnet_prefix, released)
    VALUES (?1, ?2, ?3, 0)",
                 params![container_id, suffix, subnet_prefix],
    )
    .into_diagnostic()?;

    Ok(format!("{}.{}", subnet_prefix, suffix))
}

pub fn ipam_release(container_id: &str) -> Result<()> {
    let conn = db().lock();
    conn.execute(
        "UPDATE ipam SET released=1 WHERE container_id=?1",
        params![container_id],
    )
    .into_diagnostic()?;
    Ok(())
}
