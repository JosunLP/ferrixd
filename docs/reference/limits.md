# Limits & Defaults

Every bound in the system, in one place. **Config-adjustable** limits live
in `[limits]` (see the [configuration reference](/reference/config));
**fixed** limits are protocol constants or deliberate hard bounds.

## Wire & parsing

| Limit | Value | Adjustable | Notes |
| --- | --- | --- | --- |
| Message-tags budget | 8,191 B | `max_tag_bytes` | IRCv3 tag-section budget, separate from the body |
| Message-body budget | 512 B | `max_body_bytes` | classic RFC 1459 line |
| Fatal frame length | 8,704 B | `max_line_bytes` | longer frames drop the connection; must be ≥ tags + body |
| S2S link frame | 16,384 B | fixed | separate budget for server links |
| UTF-8 | expected | — | `UTF8ONLY` advertised |

## Connection lifecycle

| Limit | Default | Adjustable | Consequence when hit |
| --- | --- | --- | --- |
| TLS handshake time | 15 s | `handshake_timeout_secs` | connection aborted |
| Registration time | 30 s | `registration_timeout_secs` | disconnect (`Registration timeout`) |
| Idle ping interval | 120 s | `ping_interval_secs` | server PINGs; second miss disconnects (`Ping timeout`) |
| Connections per IP | 10 | `max_clients_per_ip` | further connections refused |

## Flood & queue controls

| Limit | Default | Adjustable | Consequence when hit |
| --- | --- | --- | --- |
| Inbound burst | 20 commands | `recv_burst` | token bucket — |
| Inbound sustained rate | 10 commands/s | `recv_rate` | disconnect (`Excess Flood`) |
| Outbound SendQ | 2,048 lines | `sendq_lines` | disconnect (`SendQ exceeded`) |
| S2S link mailbox | 4,096 frames | fixed | link dropped |

## Names & content

| Limit | Value | Adjustable | Notes |
| --- | --- | --- | --- |
| Nick length | 30 | fixed | `NICKLEN` — enforced |
| Channel-name length | 50 | fixed | `CHANNELLEN` — enforced |
| Topic length | 390 | fixed | `TOPICLEN` — enforced (truncated) |
| Kick-reason length | 300 | fixed | `KICKLEN` — enforced (truncated) |
| Away-reason length | 200 | fixed | `AWAYLEN` — enforced (truncated) |
| Targets per PRIVMSG/NOTICE | 1 | fixed | `TARGMAX=PRIVMSG:1,NOTICE:1` |
| Mode changes per MODE | 6 | fixed | `MODES=6` |
| Ban/exception/invite entries | 100 per list | fixed | `MAXLIST` |
| Channels per client | 50 | `max_channels` | `CHANLIMIT`; opers exempt |
| MONITOR entries | 100 | fixed | `ERR_MONLISTFULL` beyond |
| SILENCE entries | 32 | fixed | `SILENCE=32`; `ERR_SILELISTFULL` beyond |
| Metadata subscriptions | 20 keys | fixed | `FAIL METADATA TOO_MANY_SUBS` beyond |
| Multiline batch | 100 lines / 4096 bytes | fixed | advertised as the `draft/multiline` cap value; exceeding either kills the batch with `FAIL BATCH MULTILINE_MAX_LINES`/`MULTILINE_MAX_BYTES` |

## Metadata (`draft/metadata-2`)

| Limit | Value |
| --- | --- |
| Keys per target | 20 |
| Key length | 32 |
| Value length | 300 |

## SASL & accounts

| Limit | Value | Notes |
| --- | --- | --- |
| SASL buffer | 8,192 B | `ERR_SASLTOOLONG` beyond |
| AUTHENTICATE chunk | 400 B | per spec |
| Password hashing | Argon2id | constant-time verify |
| SCRAM iterations | 4,096 | PBKDF2, stored-key scheme |

## History

| Limit | Default | Adjustable | Notes |
| --- | --- | --- | --- |
| Messages per target (RAM) | 500 | `history_len` | ring buffer |
| Distinct targets (RAM) | 50,000 | `history_max_targets` | LRU batch eviction |
| Messages per CHATHISTORY request | 100 max, 50 default | fixed | `CHATHISTORY=100` |
| Rows on disk | 100,000 | fixed | pruned at startup |
| Startup load | 5,000 rows | `load_limit` | `[persistence]` |
| Write batching | 256 inserts/txn | fixed | write-behind thread |
| Shutdown flush grace | 2 s | fixed | then the writer is aborted |

## Plugins & links

| Limit | Default | Adjustable | Notes |
| --- | --- | --- | --- |
| Plugin fuel per call | 5,000,000 instructions | `[plugins].fuel` | trap on exhaustion (fail-open) |
| Plugin log line | 4,096 B | fixed | truncated |
| Link reconnect delay | 30 s | fixed | dial-side retry |

## Disconnect reasons → metrics

| Reason string | Metric |
| --- | --- |
| `SendQ exceeded` | `ferrixd_sendq_drops_total` |
| `Excess Flood` | `ferrixd_flood_disconnects_total` |
| `Registration timeout` | `ferrixd_registration_timeouts_total` |
