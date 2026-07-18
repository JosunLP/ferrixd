# Observability

ferrixd exposes three windows into a running server: **Prometheus metrics**,
**structured tracing logs**, and the **`ferrixd check`** validator for
catching problems before they're running problems.

## Prometheus metrics

Enable the endpoint in the config:

```toml
[metrics]
bind = "127.0.0.1:9090"
```

Scrape `http://127.0.0.1:9090/metrics` — standard text exposition format,
no dependencies, no auth (**so bind to loopback** or a private interface
and let your Prometheus reach it there).

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ferrixd
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

What you get (full catalogue with types: [Metrics reference](/reference/metrics)):

| Metric | Watch it for |
| --- | --- |
| `ferrixd_clients` | current population; drops = netsplit or mass disconnect |
| `ferrixd_channels` | channel count |
| `ferrixd_connections_total` | accept rate; spikes = connect flood |
| `ferrixd_commands_total` / `ferrixd_messages_total` | traffic shape |
| `ferrixd_sendq_drops_total` | clients too slow to drain their queue |
| `ferrixd_flood_disconnects_total` | rate-limit kills — abuse or a broken bot |
| `ferrixd_registration_timeouts_total` | connect-and-stall behavior, port scans |
| `ferrixd_command_duration_seconds` | per-command handler latency (histogram, `command` label) |

The three `…_total` disconnect counters map one-to-one to the
[DoS controls](/internals/security#dos-controls): SendQ overflow, token
bucket exhaustion ("Excess Flood"), and registration timeout. A healthy
server shows them near zero; a server under attack shows you which control
is absorbing it.

### Alerting ideas

```yaml
# Sudden loss of >20% of clients in 5m (netsplit / crash-loop upstream)
- alert: FerrixdPopulationDrop
  expr: ferrixd_clients < 0.8 * max_over_time(ferrixd_clients[15m])
  for: 5m

# Sustained flood kills
- alert: FerrixdFloodKills
  expr: rate(ferrixd_flood_disconnects_total[5m]) > 1
  for: 10m
```

## Logging & tracing

ferrixd logs through [`tracing`](https://docs.rs/tracing) with
**per-connection spans**: every log line produced while handling a
connection carries that connection's context (remote address, nick once
registered), so one misbehaving client can be followed through the log
without grepping for guesses.

Control verbosity with the standard `RUST_LOG` grammar, either via the
environment or the CLI (the flag wins):

```sh
ferrixd --log info
ferrixd --log debug                       # verbose: per-command detail
ferrixd --log "info,ferrixd::link=debug"  # module-targeted: debug S2S only
```

Format and color:

```sh
ferrixd --log-format pretty     # human-friendly multi-line (development)
ferrixd --log-format compact    # terse single lines
ferrixd --log-format full       # default
ferrixd --color never           # for log shippers that dislike ANSI
```

Under systemd, plain stdout logging lands in the journal:

```sh
journalctl -u ferrixd -f
```

Notable events at `info` and above include listener startup, S2S link
establishment/loss (with peer names), plugin loads and traps, `OPER`
attempts, K/D-line hits, and every disconnect with its reason.

## `ferrixd check` — the third pillar

Observability starts before startup. `check` loads the config **and**
builds the TLS material, then prints a colorized summary of exactly what a
`run` would start: listeners, limits, accounts/operators/bans counts,
persistence, metrics, links, plugins.

```sh
ferrixd -c /etc/ferrixd/ferrixd.toml check
```

Non-zero exit on any problem — put it in CI and in your deploy pipeline,
and `REHASH` (or restart) only after it passes.

## Correlating the three

A worked example — "users complain about disconnects":

1. **Metrics**: `rate(ferrixd_sendq_drops_total[5m])` is climbing →
   clients aren't draining their queues.
2. **Logs**: filter for `SendQ exceeded` — the spans name the nicks and
   IPs; it's one bouncer host with a saturated uplink.
3. **Config**: decide — raise `sendq_lines` for legitimate slow consumers,
   or let the control do its job.

Every disconnect reason a control produces (`SendQ exceeded`,
`Excess Flood`, `Registration timeout`, `Ping timeout`, K-line reasons) is
both a log line and, for the first three, a metric increment — the two
views always agree.
