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
```
