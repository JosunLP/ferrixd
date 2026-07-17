# Production Deployment

A checklist-driven guide from "it runs on my laptop" to "it serves a
network". Two reference setups: **systemd** on a Linux host, and
**Docker Compose**.

## The shape of a production instance

```
                    ┌────────────────────────────────────┐
   clients ── TLS ──┤ :6697  ferrixd          [metrics]  ├── 127.0.0.1:9090 ── Prometheus
                    │        (unprivileged user)         │
   peers ── mTLS ───┤ :6666  (link_bind, firewalled)     │
                    └───────────────┬────────────────────┘
                                    │
                        /var/lib/ferrixd/ferrixd.db   (history, channels, accounts)
                        /etc/ferrixd/ferrixd.toml     (config, certs)
```

- One static binary, no runtime dependencies.
- State: **one SQLite file** (if persistence is enabled) — that's the whole
  backup story.
- Config + certificates under `/etc/ferrixd`.

## systemd

### 1. User, directories, binary

```sh
useradd --system --home /var/lib/ferrixd --shell /usr/sbin/nologin ferrixd
mkdir -p /etc/ferrixd /var/lib/ferrixd
chown ferrixd:ferrixd /var/lib/ferrixd

curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh
# → /usr/local/bin/ferrixd (running as root)
```

### 2. Config

```sh
cd /etc/ferrixd
ferrixd gen-config -o ferrixd.toml
$EDITOR ferrixd.toml
```

Production essentials in that file:

```toml
[server]
name = "irc.example.org"
network = "examplenet"
tls_bind = "0.0.0.0:6697"

[tls]
cert = "/etc/ferrixd/fullchain.pem"
key  = "/etc/ferrixd/privkey.pem"

[persistence]
path = "/var/lib/ferrixd/ferrixd.db"

[metrics]
bind = "127.0.0.1:9090"
```

Key readable by the service user, then validate:

```sh
chown root:ferrixd /etc/ferrixd/privkey.pem && chmod 640 /etc/ferrixd/privkey.pem
sudo -u ferrixd ferrixd -c /etc/ferrixd/ferrixd.toml check
```

### 3. Unit file

```ini
# /etc/systemd/system/ferrixd.service
[Unit]
Description=ferrixd — Ferrous IRC Daemon
After=network-online.target
Wants=network-online.target

[Service]
User=ferrixd
Group=ferrixd
ExecStart=/usr/local/bin/ferrixd -c /etc/ferrixd/ferrixd.toml
Restart=on-failure
RestartSec=2

# ferrixd needs nothing beyond its config, its state dir, and sockets:
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ferrixd
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
MemoryDenyWriteExecute=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now ferrixd
journalctl -u ferrixd -f
```

`MemoryDenyWriteExecute=true` works because the WASM host is an
interpreter — no JIT pages needed. Ports below 1024 aren't used, so no
capabilities are required at all.

### 4. Certificate renewal

`REHASH` reloads the certificate and key in place — no restart, no dropped
connections — so a renewal hook just refreshes the PEMs and triggers a
`REHASH`:

```sh
# /etc/letsencrypt/renewal-hooks/deploy/ferrixd
#!/bin/sh
install -o root -g ferrixd -m 640 \
    /etc/letsencrypt/live/irc.example.org/privkey.pem /etc/ferrixd/privkey.pem
install -o root -g ferrixd -m 644 \
    /etc/letsencrypt/live/irc.example.org/fullchain.pem /etc/ferrixd/fullchain.pem
# Then REHASH (e.g. via your oper tooling). A bad PEM fails the reload and
# leaves the previous certificate armed, so the listener never goes dark.
```

Existing outbound S2S links keep the certificate they handshook with until
they reconnect. If you rotate the cert those links pin, re-link them
(`SQUIT` + `CONNECT`) after the renewal.

## Docker Compose

The repository's `docker-compose.yml` is production-usable as-is:

```sh
git clone https://github.com/josunlp/ferrixd && cd ferrixd
docker build -t ferrixd .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/etc/ferrixd ferrixd gen-config
$EDITOR ferrixd.toml           # set [persistence] path = "/var/lib/ferrixd/ferrixd.db"
docker compose up -d
docker compose logs -f
```

What the compose file gives you: the `6697` port mapping, the config
bind-mount (read-only), a named volume on `/var/lib/ferrixd`, a healthcheck,
and graceful shutdown on `docker stop` (SIGTERM = Ctrl-C). Add your real
certificates as extra read-only mounts and reference them from the config.

Utility commands run through the same image:

```sh
docker compose exec ferrixd ferrixd check
docker run --rm -it ferrixd hash-password
```

## Firewalling

| Port                     | Who needs it                                          |
| ------------------------ | ----------------------------------------------------- |
| `6697/tcp`               | the world (or your users)                             |
| `6667/tcp`               | **nobody** — keep plaintext off or loopback-only      |
| `6666/tcp` (`link_bind`) | linked peers only — allowlist their addresses         |
| `9090/tcp` (metrics)     | Prometheus only — bind loopback/private, never public |

## Backup

Everything durable is the SQLite file. With WAL mode (ferrixd's default),
a consistent online backup is:

```sh
sqlite3 /var/lib/ferrixd/ferrixd.db ".backup /backup/ferrixd-$(date +%F).db"
```

The config directory (`/etc/ferrixd`) completes the picture. Restore =
stop, put both back, start.

## Upgrades

```sh
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- update
systemctl restart ferrixd
```

The installer replaces the binary atomically (safe while running), the
restart picks it up. For Docker: rebuild/pull the image, `docker compose up
-d`. Watch `ferrixd_clients` recover and skim the log for anything new.

## Pre-flight checklist

- [ ] `ferrixd check` passes as the service user
- [ ] TLS: real certs, renewal hook refreshes the PEMs and triggers `REHASH`
- [ ] `[persistence]` on, database on durable storage, backup cronjob
- [ ] `[metrics]` on loopback, Prometheus scraping, an alert or two
- [ ] `[[operators]]` use `password_hash`, one block per human
- [ ] plaintext listener absent (or loopback with a reason)
- [ ] `link_bind` firewalled to peers (if federating)
- [ ] rate limits reviewed for your audience
      ([Limits & Defaults](/reference/limits))
