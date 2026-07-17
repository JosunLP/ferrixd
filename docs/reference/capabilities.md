# IRCv3 Capabilities

ferrixd advertises **29 capabilities** in `CAP LS 302` (plus `sts` when a
policy is configured), implemented against the
[IRCv3 specifications](https://ircv3.net/ircv3.html). Negotiation
notes:

- `CAP REQ` is **all-or-nothing**: if any requested token is unknown, the
  entire request is NAK'd.
- `cap-notify` clients are informed via `CAP NEW`/`CAP DEL` if the
  advertised set ever changes.
- `sasl` carries a value (`sasl=PLAIN,EXTERNAL,SCRAM-SHA-256`), and so does
  `sts` when `[server].sts` is configured: plaintext connections see
  `sts=port=<tls-port>`, TLS connections see `sts=duration=<secs>[,preload]`.
  `sts` cannot be `REQ`ed — it is advisory only.

## The full set

| Capability | Spec status | What it gives the client |
| --- | --- | --- |
| `sasl` | ratified | authentication during registration; mechanisms `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256` — [guide](/guide/accounts) |
| `message-tags` | ratified | send/receive message tags, incl. client-only `+tags` and `TAGMSG` |
| `server-time` | ratified | `time=` tag (millisecond UTC) on all relayed messages — essential for history |
| `echo-message` | ratified | your own messages echoed back with their final tags (`msgid`, `time`) |
| `account-tag` | ratified | `account=` tag on messages from logged-in users |
| `away-notify` | ratified | `AWAY` changes broadcast to common channels |
| `extended-join` | ratified | `JOIN` carries account name and realname |
| `chghost` | ratified | in-place `user@host` changes instead of quit/rejoin fakery |
| `setname` | ratified | live realname changes via `SETNAME` |
| `multi-prefix` | ratified | all prefixes in `NAMES`/`WHO` (`@+nick`) |
| `userhost-in-names` | ratified | `NAMES` entries as full `nick!user@host` |
| `cap-notify` | ratified | `CAP NEW`/`DEL` on capability changes |
| `invite-notify` | ratified | channel ops see `INVITE`s issued by others |
| `batch` | ratified | grouped message delivery (chathistory replay, netsplits) |
| `labeled-response` | ratified | `label=` tag echoed on all responses to a labeled command — including the `echo-message` echo itself, and on the `BATCH` reference when the handler frames its own batch (CHATHISTORY). A command with no response gets a labeled `ACK` |
| `standard-replies` | ratified | machine-readable `FAIL`/`WARN`/`NOTE` — [codes ferrixd emits](/reference/commands#standard-replies-fail) |
| `account-notify` | ratified | login/logout of channel members broadcast as `ACCOUNT` |
| `extended-monitor` | ratified | `MONITOR` watchers also receive `AWAY`/`ACCOUNT`/`SETNAME`/`CHGHOST` for monitored nicks (each gated on the matching cap) |
| `no-implicit-names` | ratified | suppress the automatic `NAMES` reply on `JOIN` (explicit `NAMES` still answers) — faster joins for clients that don't need member lists |
| `sts` | ratified | strict transport security policy (`[server].sts` config); advertised per connection, never `REQ`able |
| `draft/chathistory` | draft | server-side history replay — [reference](/reference/chathistory) |
| `draft/metadata-2` | draft | key-value metadata on users and channels via `METADATA`, incl. `SUB`/`UNSUB`/`SUBS` subscriptions and push notifications when a subscribed key changes |
| `draft/multiline` | draft | multi-line messages in a batch; the cap's value carries the limits (`max-bytes=4096,max-lines=100`), which are enforced (`FAIL BATCH MULTILINE_MAX_LINES/MULTILINE_MAX_BYTES`). Capable recipients receive a real batch; everyone else gets the lines as individual messages (the spec's fallback) |
| `draft/account-registration` | draft | account self-registration via `REGISTER` |
| `draft/read-marker` | draft | per-account read markers via `MARKREAD`, synced across a user's connections |
| `draft/event-playback` | draft | `CHATHISTORY` also replays JOIN/PART/QUIT/NICK/KICK/TOPIC/MODE events |
| `draft/message-redaction` | draft | delete sent messages from history via `REDACT` (author or channel op), federated over S2S |
| `draft/channel-rename` | draft | rename channels in place via `RENAME`; non-supporting members get a PART/JOIN resync |
| `draft/pre-away` | draft | set `AWAY` before registration completes (bouncers, multi-connection clients) |
| `draft/extended-isupport` | draft | receive `RPL_ISUPPORT` during CAP negotiation, before `RPL_WELCOME` |

## Server features that are not capabilities

Some IRCv3 server features are advertised through `ISUPPORT` or user modes
rather than `CAP`, so clients never `REQ` them:

| Feature | Advertised as | Notes |
| --- | --- | --- |
| Bot mode | `ISUPPORT BOT=B`, umode `+B` | a user sets `MODE <nick> +B` to declare itself a bot; shown in `WHOIS` (`RPL_WHOISBOT`, 335), the `WHO` flags, and a bare `@bot` message tag on its messages (for `message-tags` clients). Synced across S2S links |
| UTF8ONLY | `ISUPPORT UTF8ONLY` | the wire protocol is UTF-8-validated at parse time, so non-UTF-8 content is never relayed |
| Network icon | `ISUPPORT draft/ICON=<url>` | set via `[server].icon`; a URL (ideally HTTPS, square) to the network's icon, with an optional `{size}` template |
| WEBIRC | `WEBIRC` command | trusted gateways (`[[webirc]]`) rewrite a client's apparent host/IP after a constant-time password check and a source-address allow-list |
| WebSockets | `ws://` / `wss://` listeners | `ws_bind`/`wss_bind`; negotiates the `text.ircv3.net` and `binary.ircv3.net` subprotocols, one IRC line per WebSocket message |

## A note on tagged delivery

Tags are attached **per recipient**: each client receives exactly the tags
its negotiated capability set entitles it to. A `server-time`-only client
sees `time=`; a client with `message-tags` + `account-tag` also sees
`account=` and `msgid=`; a tagless legacy client sees a bare classic line.
No client ever pays (in bytes or parsing) for a capability it didn't ask
for.

## Example negotiation

```
» CAP LS 302
« :irc.example.org CAP * LS * :sasl=PLAIN,EXTERNAL,SCRAM-SHA-256 message-tags server-time echo-message account-tag away-notify extended-join chghost setname multi-prefix …
« :irc.example.org CAP * LS :… batch draft/chathistory standard-replies draft/metadata-2 labeled-response draft/multiline draft/account-registration account-notify
» CAP REQ :sasl server-time message-tags batch labeled-response
« :irc.example.org CAP * ACK :sasl server-time message-tags batch labeled-response
» AUTHENTICATE SCRAM-SHA-256
  …
» CAP END
```

## Compatibility

Draft capabilities (`draft/` prefix) track their specifications; when a
draft is ratified, ferrixd will advertise the ratified name (and, per
`cap-notify`, connected clients learn about it live). Clients that
negotiate nothing get a well-behaved RFC 1459 server — every modern
behavior is opt-in via CAP.
