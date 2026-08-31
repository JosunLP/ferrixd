# Metrics

The Prometheus catalogue served at `[metrics].bind` (`/metrics`, text
exposition format `0.0.4`). Setup and alerting ideas:
[Observability guide](/guide/observability).

## Gauges

Read live at scrape time.

| Metric | Help |
| --- | --- |
| `ferrixd_clients` | Currently connected clients |
| `ferrixd_channels` | Currently existing channels |

## Counters

Monotonic since process start.

| Metric | Help | Incremented when |
| --- | --- | --- |
| `ferrixd_connections_total` | Connections accepted | a connection reaches the session loop — i.e. past the D-line check, the per-IP throttle, and (on the TLS listener) the handshake, but before registration |
| `ferrixd_commands_total` | Commands dispatched | any client command is dispatched |
| `ferrixd_messages_total` | Messages relayed | a PRIVMSG/NOTICE is delivered |
| `ferrixd_sendq_drops_total` | SendQ-overflow disconnects | a client is dropped with `SendQ exceeded` |
| `ferrixd_flood_disconnects_total` | Excess-flood disconnects | the token bucket kills a client (`Excess Flood`) |
| `ferrixd_registration_timeouts_total` | Registration-timeout disconnects | an unregistered connection exceeds `registration_timeout_secs` |

The three disconnect counters correspond one-to-one to the
[DoS controls](/internals/security#dos-controls) and to identically-worded
log lines — metrics and logs always agree on why a client left.

## Histograms

| Metric | Help |
| --- | --- |
| `ferrixd_command_duration_seconds` | Command handler latency, per command |

`ferrixd_command_duration_seconds` is a per-command histogram of how long the
handler took, carrying a `command` label. Buckets (seconds): `5e-05`, `0.0001`,
`0.00025`, `0.0005`, `0.001`, `0.005`, `0.025`, `0.1`, `+Inf`; the usual
`_bucket`, `_sum`, and `_count` series are emitted. Label cardinality is
**bounded**: unknown or unhandled verbs collapse to `command="other"`, so a
client sending arbitrary command names cannot inflate the series set.

## Plugin counters

Emitted only when the [WASM plugin host](/guide/plugins) has plugins loaded,
one series per plugin (`plugin` label, the file stem):

| Metric | Help |
| --- | --- |
| `ferrixd_plugin_calls_total` | Plugin hook invocations |
| `ferrixd_plugin_blocks_total` | Events blocked by a plugin (veto hooks only — an observe-only hook's return value is discarded and never counted) |
| `ferrixd_plugin_traps_total` | Plugin traps and fuel exhaustions |

`ferrixd_plugin_traps_total` is the one to alert on: the host fails **open**,
so a trapping plugin quietly stops enforcing whatever policy it was loaded for
while everything else keeps working.

```promql
increase(ferrixd_plugin_traps_total[15m]) > 0
```

Label cardinality is bounded by the number of `.wasm` files in `[plugins].dir`.

## Endpoint behavior

- Plain HTTP/1.1, hand-rolled responder — every request path returns the
  same `200 OK` body with `Content-Type: text/plain; version=0.0.4`, then
  the connection closes.
- **No authentication, no TLS** on this endpoint by design — bind it to
  loopback or a private interface only.

## Useful queries

```text
# connect rate (attacks show up here first)
rate(ferrixd_connections_total[1m])

# messages per second, network-visible activity
rate(ferrixd_messages_total[5m])

# who is absorbing abuse: flood-kills vs sendq drops vs registration stalls
rate(ferrixd_flood_disconnects_total[5m])
rate(ferrixd_sendq_drops_total[5m])
rate(ferrixd_registration_timeouts_total[5m])

# population trend
ferrixd_clients

# p99 handler latency per command (needs a scrape range)
histogram_quantile(0.99, sum by (le, command) (rate(ferrixd_command_duration_seconds_bucket[5m])))
```
