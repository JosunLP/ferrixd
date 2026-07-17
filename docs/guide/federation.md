# Federation (S2S)

ferrixd servers link into a **federated network**: users on different servers share
channels, exchange messages and WHOIS, and see consistent state — topics,
modes, kicks, away status, accounts — network-wide. Links are multi-hop
(tree topology, **enforced**: a link that would close a cycle is refused),
survive server restarts via automatic reconnect, and clean up after
themselves on netsplit.

The protocol is ferrixd-native — modern, minimal, and documented in the
[S2S protocol reference](/reference/s2s-protocol). To federate with an
existing charybdis-family network (solanum, …), mark a link with
`protocol = "ts6"` — see [Bridging to TS6 IRCds](#bridging-to-ts6-ircds)
below.

## Trust model

A link is authorized by **two independent factors**:

1. **Pinned TLS certificate fingerprint.** Each side pins the other's
   certificate SHA-256 in its config. No CA involved — trust is explicit
   and per-peer.
2. **Shared link password**, compared in constant time during the
   handshake.

Both must match, over mutual TLS, before a single state frame is accepted.
There is no plaintext link mode.

## Linking two servers, step by step

Assume `irc1.example.org` (SID `A01`) and `irc2.example.org` (SID `B02`).

### 1. Give each server an identity

Each server needs a network-unique **SID** and (on at least one side) a
link listener:

```toml
# irc1 — will accept the link
[server]
name = "irc1.example.org"
sid = "A01"
link_bind = "0.0.0.0:6666"
```

```toml
# irc2 — will dial out
[server]
name = "irc2.example.org"
sid = "B02"
```

::: warning Same network, same rules
`casemapping`, and `cloak_key` if you use cloaking, must be identical on
all linked servers — they define network-wide semantics.
:::

### 2. Exchange certificate fingerprints

On each server, print the fingerprint of its **own** TLS certificate:

```sh
ferrixd fingerprint /etc/ferrixd/cert.pem
```

Servers present their regular `[tls]` certificate on links; a stable
self-signed pair from `ferrixd gen-cert` is perfectly fine here, because
validation is by pinned fingerprint, not CA.

### 3. Configure the peers

```toml
# irc1 — accept-only: no `connect`
[[links]]
name = "irc2.example.org"
fingerprint = "<irc2's cert sha256, lowercase hex>"
password = "shared-link-secret"
```

```toml
# irc2 — dials irc1
[[links]]
name = "irc1.example.org"
connect = "irc1.example.org:6666"
fingerprint = "<irc1's cert sha256>"
password = "shared-link-secret"
```

`name` must match the peer's advertised `server.name` — a mismatch aborts
the handshake.

### 4. Restart and watch

Restart both servers to start the config-driven auto-dial loops. The
dialing side retries every 30 seconds until the link is up, and re-dials
automatically after any drop. In the logs you'll see the handshake, then
the **burst**.

### Managing links at runtime

You don't have to restart to touch a link once the server is running:

- **`CONNECT <name>`** dials a configured peer immediately (one attempt).
  Use it to bring up a link you just added — `REHASH` first so the new
  `[[links]]` block is loaded, then `CONNECT <name>`.
- **`SQUIT <server> [:reason]`** disconnects a directly-linked peer, by
  server name or SID. The peer and everything reachable through it split
  off through the normal netsplit path.

Both are operator commands (`481 ERR_NOPRIVILEGES` without the flag;
`402 ERR_NOSUCHSERVER` for an unknown name). `REHASH` refreshes the stored
`[[links]]` definitions (so `CONNECT` sees edits) but does not itself
start or stop the boot-time auto-dial loops — use `CONNECT`/`SQUIT` for
that.

## What happens at link-up

On a successful handshake, each side bursts its state to the other:

1. **Users** — every local (and known remote) user with nick, user, host,
   account, and away status.
2. **Channels** — memberships with op/voice prefixes, topics (with setter
   and timestamp), non-default modes, and the full ban/exception/invite
   lists.

From then on, deltas flow in both directions and are **forwarded loop-free**
along the link tree, so any tree of N servers converges — you can chain
`A — B — C` and users on A and C share channels through B.

### Loop prevention

Topologies are trees, and ferrixd **enforces** that. Servers propagate the
network topology to each other (each server introduction carries the SID,
name, and uplink), so every server knows every other server and how it is
reached. A handshake or introduction naming a server that is already in the
network — by SID or by name — would close a cycle and is refused:

```
ERROR :Server irc3.example.org (C03) is already reachable via B02 — link would create a loop
```

If you configure redundant links (say `A — B`, `B — C`, *and* `C — A`), the
first two to come up win; the third is refused and keeps retrying every 30
seconds, so it acts as a warm standby: after a real split it is the first to
re-close the gap. The network never runs with an active cycle.

## Bridging to TS6 IRCds

A link can speak **TS6** — the S2S protocol of the charybdis family
(solanum, ratbox, …) — instead of the native protocol. Mark it in the
config; everything else (fingerprint pinning, password, connect/accept) is
identical:

```toml
[[links]]
name = "irc.solanum.example"
connect = "irc.solanum.example:7001"
fingerprint = "<solanum cert sha256, lowercase hex>"
password = "shared-link-secret"
protocol = "ts6"
```

On the solanum side this is a regular `connect {}` block with
`ssl_connect`/fingerprint verification. ferrixd performs the TS6 handshake
(`PASS … TS 6`, `CAPAB`, `SERVER`, `SVINFO`), then translates at the edge:

- users cross as `EUID` (nick, host, account, realname), channels as
  `SJOIN` with `@`/`+` prefixes plus `TMODE`/`TB` for modes and topics —
  the channel timestamp is carried and resolved in both directions;
- messages, away state, account logins (`ENCAP LOGIN`/`SU`), kicks, kills,
  operator broadcasts (`WALLOPS`/`OPERWALL`/`GLOBOPS`), host changes
  (`CHGHOST`), invitations, nick-collision `SAVE`s, and netsplits translate
  in both directions;
- ferrixd UIDs are not TS6-shaped, so the bridge maintains a per-link
  **UID alias table** — TS6 peers see well-formed nine-character IDs under
  the correct SID, and replies to those aliases map back transparently.

The rest of your ferrix network needs no changes: state arriving from the
TS6 side is re-announced to other links in the native protocol, multi-hop
routing and loop prevention included.

::: warning Scope
TS6 has no equivalent for a few ferrix frames, which are therefore dropped
at the bridge: `TAGMSG` (client-only tags), `REDACT`
(draft/message-redaction), `RENAME` (draft/channel-rename), `SETNAME`, and
network bans (`GLINE`). Relayed messages also lose their origin `msgid` and
`server-time` across the bridge — the far side mints its own. Use the bridge
to connect a ferrix network to a TS6 network you also operate — one
authenticated bridge link, tree topology as always — not to join an
adversarial mesh. Your `sid` must be TS6-shaped
(`[0-9][A-Z0-9][A-Z0-9]`, e.g. `1AA`) for the bridge to start.
:::

## Life on a linked network

Everything just works, with attribution preserved:

- `PRIVMSG`/`NOTICE` to users and channels on any server (fan-out is
  deduplicated per server link).
- `WHO`/`WHOX` and `WHOIS` for remote users (`WHOIS` shows which server
  they're on).
- `JOIN`/`PART`/`KICK`/`TOPIC`/`MODE`/`AWAY`/account changes propagate.
- `KILL` by an oper reaches users on any server.
- `NAMES` shows remote members alongside local ones.

### Nick collisions

Nick uniqueness is enforced without synchronized clocks:

- A nick already held **anywhere** on the network is simply refused locally
  (`433`).
- A genuine simultaneous collision (two users grab the same nick during a
  split, then the servers link) is resolved **deterministically**: the
  smaller network UID wins, the loser is killed. Both sides compute the
  same answer independently — no timestamp negotiation, no desync.

Event ordering across the mesh uses **Lamport logical clocks**, so no NTP
requirement exists anywhere in the protocol.

### Netsplits

When a link drops — `SQUIT`, crash, network partition — each side:

1. determines every server that was reachable **only** through the dead
   link (the whole subtree, in multi-hop topologies);
2. removes those servers' users from all channels;
3. announces the departures locally with the classic quit reason
   `*.net *.split`.

When the link returns (auto-reconnect), a fresh burst restores the shared
state. Channel history is per-server, so `CHATHISTORY` can backfill what a
split hid from you if your server hosted the channel members that kept
talking.

## Security properties worth knowing

These are enforced per-frame, not assumed:

- **Origin authorization.** The first peer to announce a SID owns its
  route. Every subsequent state frame is validated against the link it
  arrived on — a peer cannot speak for servers it doesn't route, cannot
  spoof your own SID back at you, and forged frames are dropped and logged.
  The same checks apply on TS6 bridge links.
- **Cycle refusal.** A handshake or server introduction that names an
  already-known SID or server name is answered with `ERROR` and the link is
  dropped — the network cannot be tricked (or misconfigured) into a
  message-duplicating loop.
- **Constant-time password check**, pinned certificate, and a 16 KiB frame
  budget on link lines.
- **Bounded link mailbox** (4096 frames) — a stalled peer cannot balloon
  local memory.

## Operational checklist

- [ ] Unique `sid` per server; stable — changing it is a rejoin.
- [ ] `casemapping` (and `cloak_key`, if used) identical network-wide.
- [ ] Fingerprints re-pinned whenever a peer rotates its TLS certificate.
- [ ] `link_bind` firewalled to peer addresses — it speaks only the link
      protocol, but there's no reason to expose it.
- [ ] Distinct `password` per link pair.
- [ ] Watch `ferrixd_clients` on both sides after linking — a successful
      burst shows the remote population immediately.
