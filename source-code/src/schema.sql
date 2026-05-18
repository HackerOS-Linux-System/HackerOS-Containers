-- HackerOS Container Runtime — SQLite schema v1
-- Embedded via include_str! in db.rs

CREATE TABLE IF NOT EXISTS containers (
    id           TEXT    PRIMARY KEY,
    name         TEXT    NOT NULL UNIQUE,
    image        TEXT    NOT NULL DEFAULT 'unknown',
    pid          INTEGER NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'Running',
    ip_address   TEXT,
    veth_host    TEXT,
    bundle_path  TEXT    NOT NULL DEFAULT '',
    ports_json   TEXT    NOT NULL DEFAULT '[]',
    pod_id       TEXT,
    auto_restart INTEGER NOT NULL DEFAULT 0,
    config_json  TEXT    NOT NULL DEFAULT '{}',
    created_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_containers_name   ON containers(name);
CREATE INDEX IF NOT EXISTS idx_containers_status ON containers(status);

CREATE TABLE IF NOT EXISTS pods (
    name                TEXT    PRIMARY KEY,
    container_ids_json  TEXT    NOT NULL DEFAULT '[]',
    status              TEXT    NOT NULL DEFAULT 'Running',
    shared_network      INTEGER NOT NULL DEFAULT 1,
    shared_pid          INTEGER NOT NULL DEFAULT 1,
    shared_ipc          INTEGER NOT NULL DEFAULT 1,
    netns_path          TEXT,
    spec_json           TEXT    NOT NULL DEFAULT '{}',
    created_at          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ipam (
    container_id   TEXT    PRIMARY KEY,
    suffix         INTEGER NOT NULL UNIQUE,
    subnet_prefix  TEXT    NOT NULL DEFAULT '10.10.0',
    released       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ipam_released ON ipam(released);
