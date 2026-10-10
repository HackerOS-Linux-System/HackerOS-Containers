# HackerOS Containers (`hco`)

A container manager for HackerOS written in **H#**, built on two [bit](https://github.com/bit-io/bit) libraries:

| library | what hco uses it for |
|---|---|
| [`container`](https://github.com/bit-io/container) | OCI images, local store, registry pull/push, Containerfile builds, the native runtime (namespaces, pivot_root, cgroups, bridge networking), container state |
| [`colors`](https://github.com/bit-io/colors) | the whole CLI: gradient banner, aligned tables, status badges, usage bars, themed messages (colours switch off automatically when stdout is not a terminal, or with `NO_COLOR` / `--no-color`) |

On top of them hco adds pods, restart policies, hardening presets, seccomp profiles, declarative stacks, health checks, an event log, a REST API and Prometheus metrics.

## Build

```sh
bit build          # reads Bit.hk, installs container + colors, builds a static binary
cache/build/release/hco doctor
```

`Bit.hk` uses the current format (`[edition]`, `[layout]`, `[build] link => static`, `[default-build]`, `[dependencies]`, `[commands]`, `[hooks]`). Handy commands: `bit check`, `bit install-local`.

## Quick tour

```sh
hco pull alpine:3.20
hco run -d --name web -p 8080:80 -m 256m --restart on-failure --preset web nginx:alpine
hco ps
hco stats                 # live CPU / memory bars
hco logs -f web
hco exec web sh
hco inspect web
```

### Commands

| area | commands |
|---|---|
| containers | `run` `create` `start` `stop` `restart` `kill` `rm` `ps` `logs` `exec` `inspect` `top` `stats` `wait` `rename` `port` `health` `prune` `supervise` |
| images | `images` `pull` `build` `rmi` `tag` `history` `save` `load` `import` `push` `login` `logout` `image …` |
| pods | `pod create / ls / inspect / start / stop / restart / rm`, `hco run --pod NAME` |
| volumes | `volume create / ls / inspect / rm / prune` (`-v name:/path`) |
| network | `network ls / inspect / attach / detach` (CNI via `cnitool`), `port` |
| stacks | `up` / `down` with a `.hk` file ([example](examples/hco.hk)) |
| security | `preset ls / show`, `seccomp ls / show / install / run` |
| service | `serve`, `api token`, `tls init / show`, `metrics` |
| system | `doctor` `info` `df` `events` `config` `system prune` `completion bash|zsh|fish` `version` |

Global options: `--root DIR`, `--driver vfs|overlay`, `--no-color`.

### Run options

`-d --rm --name --hostname -w -u -e -v -p -m --cpus --pids-limit --cpu-shares --read-only --privileged --network bridge|host|none --entrypoint --cap-add --cap-drop -l --env-file --restart no|on-failure|always|unless-stopped --pod --preset --health-cmd --health-interval --seccomp`

Presets (`hco preset ls`): `hardened` (read-only rootfs, all capabilities dropped, 512 pids), `strict`, `web`, `batch`.

### Restart policies

Policies are applied by `hco supervise` (`hco supervise --once` for cron, or the `hco-supervisor.service` unit).

### Stack files

```
! hco.hk
[stack]
-> name => shop

[db]
-> image => postgres:16-alpine
-> restart => always

[web]
-> image => nginx:alpine
-> publish => 8080:80
-> depends_on => db
```

`hco up` creates a pod named after the stack and starts the services in dependency order. The pre-2026 `key = value` form is still read.

## REST API

Compiled H# has no HTTP server, so the API is served the Unix way: a listener runs `hco api-conn` once per connection (stdin/stdout).

```sh
hco api token                      # create / show the bearer token
hco serve --bind 127.0.0.1:7443    # needs socat; add --tls after `hco tls init`
curl -H "Authorization: Bearer $(hco api token | tail -1)" http://127.0.0.1:7443/containers?all=1
```

Endpoints: `GET /health` (no auth) `/version` `/metrics` `/containers` `/containers/<id>` `/containers/<id>/logs` `/images` `/pods`, `POST /containers/<id>/start|stop|restart|kill`, `DELETE /containers/<id>`.

With systemd: install `services/hco-api.socket` and `services/hco-api@.service` (socket activation, `Accept=yes`).

## State

The `container` library keeps images and container state in its store (`/var/lib/container`, or `CONTAINER_ROOT`). hco keeps its own small files in `<store>/hco/` (metadata, pods, event log, TLS, seccomp, API token) — no database is needed.

## Layout

```
src/main.h#       dispatcher, help
src/ui.h#         colors-based CLI toolkit (banner, tables, badges, bars)
src/args.h#       argument parser
src/backend.h#    store helpers on top of the container library
src/container.h#  lifecycle, ps, logs, exec, inspect, health, supervisor
src/image.h#      image commands
src/pod.h#  volume.h#  network.h#  cni.h#  stack.h#  config.h#
src/metrics.h#    stats, top, Prometheus
src/seccomp.h#  sandbox.h#  tls.h#  api.h#  system.h#
src/db.h#  validation.h#  logging.h#  utils.h#
services/         systemd units
examples/hco.hk   example stack
```

## Notes

* Most operations need root (mounts, cgroups, bridge networking); `hco doctor` shows what is available.
* The built-in runtime does not install seccomp filters. `hco seccomp run ID --profile NAME` runs a created container through `crun`/`runc` with a profile patched into its OCI bundle (needs `jq`).
