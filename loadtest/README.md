# ferrixd load generator

A standalone tool (excluded from the main workspace so it needn't satisfy the
daemon's strict lints) that opens many concurrent IRC connections, registers
each, optionally joins a channel, and holds the connections open so the server's
resource use can be measured.

```sh
cargo run --release -- <host:port> <count> [src_ips] [hold_secs] [chan_bucket]
# e.g. 100k connections across 4 loopback source IPs, held 45s, no channel:
cargo run --release -- 127.0.0.1:6667 100000 4 45 0
```

`src_ips` spreads sockets across `127.0.0.1 … 127.0.0.N`. A single
`(src_ip, dst_ip:port)` pair is limited to the ~28k ephemeral ports in
`/proc/sys/net/ipv4/ip_local_port_range`, so reaching 100k from one machine
requires ≥4 source addresses. `chan_bucket` groups clients into channels of that
size (`0` = don't join); grouping keeps channel fan-out bounded so a density run
doesn't become an O(N²) broadcast storm.

## Results

Measured on an 8-core / 31 GB Linux host, ferrixd release build, **plaintext**
listener, clients from 4 loopback source IPs, `max_clients_per_ip` raised.

| Connections | Server RSS | Per-connection | OS threads |
|------------:|-----------:|---------------:|-----------:|
| 0 (baseline)| 6.0 MB     | —              | 9          |
| 10,000      | 144 MB     | ~13.8 KB       | 9          |
| **99,750**  | **1.38 GB**| **~13.8 KB**   | **9**      |

Observations:

- **Linear memory.** Per-connection cost is identical (~13.8 KB) at 10k and
  100k — no super-linear blow-up from the registries or the channel/nick maps.
  Extrapolating, ~1M connections would need ~14 GB of connection state.
- **Constant thread count.** The daemon stays at 8 worker threads + 1 regardless
  of connection count: it is one async *task* per connection (green-scheduled),
  not one OS thread. This is why memory, not scheduler overhead, is the limit.
- **99.7% registered** (99,739 / 100,000) — the shortfall is a handful of
  duplicate-nick / timing losses in the generator, not server refusals.
- **Establishment ~1,600 conn/s** here, but that is *client*-limited (one
  machine driving both ends); the server never refused or flood-killed a
  connection during the ramp.

## Tuning notes (for a real 100k+ deployment)

- **File descriptors:** `ulimit -n` ≥ connections + headroom (we ran with 1 M).
- **Ephemeral ports / source IPs:** widen `ip_local_port_range` and/or accept on
  several addresses; a single client IP tops out near 28k.
- **Listen backlog:** raise `net.core.somaxconn` for large accept bursts.
- **`max_clients_per_ip`:** the daemon's per-IP throttle must be raised when many
  clients share a source IP (as in this loopback test).
- **TLS:** these figures are for the plaintext listener, which isolates the
  connection-handling cost. Real deployments are TLS-only; rustls session state
  adds on the order of tens of KB per connection, so budget RAM accordingly.
