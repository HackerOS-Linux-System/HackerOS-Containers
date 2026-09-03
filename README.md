# hco — HackerOS Containers

Ten workspace to przepisanie projektu **HackerOS-Containers** (oryginalnie
Rust/Cargo) na **H#** i zorganizowanie go jako workspace budowany przez
**Bytes** (`Bytes.hk`).

## Struktura

```
Bytes.hk                 workspace manifest (Bytes)
hco-core/
  Bytes.hk                package manifest
  src/
    main.h#               CLI (dawniej main.rs)
    config.h#              HkConfig + parser .hk (dawniej config.rs)
    utils.h#                dawniej utils.rs
    validation.h#           dawniej validation.rs
    db.h#                    SQLite state store (dawniej db.rs)
    schema.sql               NIEZMIENIONY
    image.h#                 pull/bundle/GC obrazów (dawniej image.rs)
    sandbox.h#                namespaces/cgroups (dawniej sandbox.rs)
    seccomp.h#                 profile seccomp (dawniej seccomp.rs)
    network.h#                  bridge/veth/NAT (dawniej network.rs)
    cni.h#                       CNI (dawniej cni.rs)
    tls.h#                        TLS (dawniej tls.rs)
    logging.h#                     logi kontenerów (dawniej logging.rs)
    metrics.h#                      cgroup + Prometheus (dawniej metrics.rs)
    container.h#                     orkiestracja kontenera (dawniej container.rs)
    pod.h#                            grupy kontenerów (dawniej pod.rs)
    api.h#                             REST API (dawniej api.rs)
    sys_ffi.h#                         [NOWY] surowe wiązania libc
services/
  hco-api.service           jednostka systemd (dostosowana do nowego CLI)
  hco-api.socket            NIEZMIENIONY (poza portem)
build.hl / install.hl / remove.hl   skrypty Bytes/H-Sharp
```

## Budowanie

```
bytes build --release
```

albo:

```
hl build.hl
```
