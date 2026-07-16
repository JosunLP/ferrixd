# S2S Protocol

The ferrixd server-to-server link protocol — modern, minimal, and distinct
from TS6. (Links to TS6 IRCds are possible through the [TS6
bridge](/guide/federation#bridging-to-ts6-ircds), which translates between
this protocol and TS6 at the edge of the network.) Operational guide:
[Federation](/guide/federation).

## Transport

- **Mutual TLS.** The dialing side verifies the peer's certificate against
  the pinned SHA-256 fingerprint from `[[links]]` before speaking; each
  server presents its own `[tls]` certificate.
- **Line-oriented**, reusing the IRC message grammar (same parser, same
  escaping), with a dedicated frame budget of **16,384 bytes** per line.
- **Bounded mailbox** — each link's outbound queue holds 4096 frames; a
  peer that stops reading is disconnected rather than ballooning memory.
- **Reconnect** — the dialing side retries every 30 seconds, forever.

## Handshake

Both sides send, immediately upon connect:

```
PASS <shared-secret>
SERVER <name> <sid> :<description>
```

Each side validates: the `PASS` token (constant-time comparison), and that
`SERVER <name>` matches the peer name configured for this link. Any
mismatch aborts with `ERROR`. Finally, **loop prevention**: if the peer's
SID or name is already present in the network (our own identity, another
direct link, or a server reachable through one), the link would close a
cycle and is refused with `ERROR :Server … already exists`. After the
handshake, both sides **burst** (below), then exchange deltas.
`PING`/`PONG` keep the link verified.

## Ordering: Lamport clocks

Events carry a **Lamport logical clock** — a monotonic counter merged on
receive (`observe`), incremented on send (`tick`). This gives the network
a consistent happens-before ordering with **no synchronized wall clocks**;
there is no TS6-style timestamp negotiation and no clock-skew failure
mode. Deterministic tie-breaks (e.g. nick collisions) use network UIDs,
which both sides compute identically.

## Message kinds

Users are identified by network-unique **UIDs** (`<sid>` + local id);
channel-membership and mode arguments always use UIDs, never nicks.

### Session / topology

| Frame | Meaning |
| --- | --- |
| `PASS <token>` | handshake secret |
| `SERVER <name> <sid> :<desc>` | identity announcement (handshake only) |
| `SSERVER <name> <sid> <uplink> :<desc>` | introduce a server elsewhere in the network (`uplink` = its tree parent's SID); an introduction of an already-known SID or name is a detected cycle → `ERROR`, link drop |
| `PING <token>` / `PONG <token>` | liveness |
| `SQUIT <sid> :<reason>` | a server (subtree) is leaving the network; forwarded so every server splits the same subtree |
| `ERROR :<reason>` | fatal link error, connection closes |

### Users

| Frame | Meaning |
| --- | --- |
| `UID <sid> <uid> <lamport> <nick> <user> <host> <account> :<realname>` | introduce a user (`account` is `*` when logged out) |
| `NICK <uid> <newnick>` | nick change |
| `QUIT <uid> :<reason>` | user left |
| `SAWAY <uid> [:<reason>]` | away set/cleared |
| `SACCOUNT <uid> <account\|*>` | login/logout |
| `SSETNAME <uid> :<realname>` | realname change (`setname`) |
| `SCHGHOST <uid> <host>` | displayed-host change (`chghost`) |
| `KILL <uid> :<reason>` | forced disconnect (routed toward the user's server) |

### Channels

| Frame | Meaning |
| --- | --- |
| `SJOIN <channel> <uid> <flags> <ts>` | membership (`flags`: `o`, `v`, `ov`, or `-`); `ts` is the sender's channel-creation time |
| `SPART <channel> <uid> :<reason>` | leave |
| `SKICK <channel> <source> <target> :<reason>` | kick, attributed |
| `STOPIC <channel> <source> <setby> <setat> :<text>` | topic with provenance |
| `SMODE <channel> <source> <ts> <flags> [args…]` | mode change (o/v args are UIDs); modes from a *younger* view of the channel are ignored |
| `SUMODE <uid> <flags>` | user modes (`+o`, `+i`) — keeps oper status visible network-wide |
| `SKNOCK <source> <channel> :<mask>` | a knock on an invite-only channel, delivered to that channel's ops on every server |
| `SINVITE <source> <target> <channel>` | cross-server invitation, routed toward the target's server, which records the pending invite and notifies the target |
| `SRENAME <source> <old> <new> :<reason>` | channel rename (draft/channel-rename): every server moves the channel, its history and registration to the new name and resyncs local members |

### Messages

| Frame | Meaning |
| --- | --- |
| `SMSG <source> <target> <P\|N> <msgid\|*> <time_ms\|*> <tags\|*> :<text>` | direct message relay (`P`RIVMSG / `N`OTICE); carries the origin's msgid, send time and client-only tags so every server shows the same message identity (`*` = absent → the receiver mints; the 4- and 6-param legacy forms are still parsed) |
| `SCMSG <source> <channel> <P\|N> <msgid\|*> <time_ms\|*> <tags\|*> :<text>` | channel message relay; a STATUSMSG target keeps its `@`/`+` sigil |
| `STAGMSG <source> <target> :<tags>` | tags-only message (`TAGMSG`) — typing/react/reply reach members on other servers |
| `SREDACT <source> <target> <msgid> :<reason>` | message redaction (draft/message-redaction): flooded; every server deletes the message from its history and tells capable local clients |

### Network-wide operator actions

| Frame | Meaning |
| --- | --- |
| `SWALLOPS <source> :<text>` | operator broadcast, fanned out to `+w` users on every server |
| `SBAN <+\|-> <mask> <setby> :<reason>` | network ban (G-Line) add/remove, applied as a local K-Line everywhere |

Like `KILL`, these are trusted network-wide (every link is mutually
authenticated); they are flooded to all links rather than routed.

## Burst

Immediately after the handshake, each side sends the other its view of the
network:

1. the **topology** — every other server it knows (`SSERVER`), parents
   before children, so each `uplink` and each user's SID below is already
   introduced;
2. every local user (`UID`, plus `SAWAY` and `SUMODE` where set);
3. every remote user it routes for **other** links (excluding the peer's
   own users, avoiding echo);
4. per channel: memberships with prefixes (`SJOIN`, carrying the channel's
   timestamp), the topic (`STOPIC`), non-default modes (`SMODE` with source
   `*`), the ban/exception/invite lists chunked six masks per `SMODE`, and
   any outstanding invitations (`SINVITE` with source `*`);
5. a closing `PING` as the **end-of-burst** marker, so the peer can tell
   when it has the complete picture.

## Channel timestamps (netjoin conflicts)

When both sides independently created the same channel, the **older channel
wins** (the TS6 rule). `SJOIN`/`SMODE` therefore carry the sender's
channel-creation timestamp:

- the peer's channel is **older** → we adopt its timestamp and wipe our
  modes and every member's status (for the winner, our channel never
  existed); local members see the resulting `MODE` deltas;
- the peer's channel is **younger** → we keep ours; the joining members
  arrive with no status and the peer's burst modes are ignored;
- equal (or `0`, i.e. unknown — a legacy peer) → the views are merged.

## Routing & security invariants

Enforced on every inbound frame:

- **Route ownership.** The first link to announce a SID owns the route to
  it. A server's own SID is never accepted from a peer.
- **Tree enforcement.** Registering a link claims its SID's route
  atomically; a handshake or `SSERVER` introduction whose SID or name is
  already owned elsewhere is refused (`ERROR`) — the network never runs
  with an active cycle.
- **Origin authorization.** Every user-scoped frame must arrive on the
  link that owns the originating SID's route — a peer cannot speak for
  users or servers it does not route. Violations are dropped and logged.
- **Loop-free forwarding.** Authorized frames are re-forwarded to every
  *other* link (spanning-tree flooding), so multi-hop topologies converge
  without duplicate delivery; channel fan-out is deduplicated per link.
- **UID collisions** resolve deterministically: the smaller network UID
  wins; the loser's server receives a `KILL` for its user.

## Netsplit semantics

On link loss (transport EOF, `ERROR`, or `SQUIT`): every SID reachable
only through that link is removed transitively; all its users are quit
locally with reason `*.net *.split`; channel memberships are cleaned up
and empty channels disappear. A later reconnect triggers a fresh burst —
state re-converges from scratch rather than trusting a stale delta stream.
