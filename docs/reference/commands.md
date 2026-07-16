# IRC Commands

Every client command ferrixd handles. Unknown commands receive
`421 ERR_UNKNOWNCOMMAND`; commands other than the registration set sent
before registration receive `451 ERR_NOTREGISTERED`.

Legend: **○** available pre-registration · **⚙** requires IRC operator ·
**@** requires channel operator (context-dependent).

## Connection & registration

| Command | | Description |
| --- | --- | --- |
| `CAP LS 302` / `REQ` / `END` / `LIST` | ○ | capability negotiation; `REQ` is all-or-nothing — one unknown token NAKs the whole request |
| `AUTHENTICATE <mech\|payload\|*>` | ○ | SASL (`PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`); 400-byte chunking; `*` aborts |
| `PASS <password>` | ○ | connection password; required before registration completes when `[server].password` is configured (464 otherwise) |
| `NICK <nick>` | ○ | set/change nick (≤ 30 chars; refused if held anywhere on the network) |
| `USER <user> 0 * :<realname>` | ○ | complete registration |
| `PING <token>` / `PONG` | ○ | keepalive (client `PONG` answers the server's idle ping) |
| `QUIT [:<reason>]` | ○ | disconnect gracefully |

## Messaging

| Command | | Description |
| --- | --- | --- |
| `PRIVMSG <target> :<text>` | | message a channel or user; single target per command (`TARGMAX=PRIVMSG:1`); recorded in history; may be vetoed by a [plugin](/guide/plugins) (`FAIL PRIVMSG MSG_BLOCKED`) |
| `NOTICE <target> :<text>` | | as PRIVMSG, but never generates automatic replies |
| `TAGMSG <target>` | | client-tags-only message (reactions, typing indicators) — requires `message-tags` |
| `BATCH +<ref> <type>` … `BATCH -<ref>` | | client-initiated batches; `draft/multiline` batches are accepted (≤ 100 lines) |
| `AWAY [:<reason>]` | | set/clear away state (`away-notify` broadcasts to common channels; propagated over S2S) |
| `SETNAME :<realname>` | | change realname live (`setname` cap; propagated over S2S) |

STATUSMSG: `PRIVMSG`/`NOTICE` to `@#chan` or `+#chan` deliver only to
members holding at least that prefix (advertised as `STATUSMSG=@+`).
Status-targeted messages are not recorded in the shared channel history.

## Channels

| Command | | Description |
| --- | --- | --- |
| `JOIN <#chan>[,<#chan>…] [key…]` | | join; enforces `+k`/`+b`/`+i`/`+l` and `max_channels`; plugin `on_join` may veto (`FAIL JOIN JOIN_BLOCKED`) |
| `PART <#chan>[,…] [:<reason>]` | | leave |
| `TOPIC <#chan> [:<text>]` | @ | get, or set (op-only while `+t` — the default) |
| `MODE <#chan> [modes…]` | @ | query or change channel modes — full table in [Modes & ISUPPORT](/reference/modes); ≤ 6 changes per command |
| `KICK <#chan> <nick> [:<reason>]` | @ | remove a member |
| `INVITE [<nick> <#chan>]` | @ | invite (op-only when `+i`); `invite-notify` informs other ops; works cross-server; with no arguments lists your pending invitations (336/337) |
| `KNOCK <#chan>` | | ask the ops of an invite-only channel for an invitation (710 to ops, 711 to you) |
| `NAMES <#chan>` | | member list with prefixes (`multi-prefix`, `userhost-in-names` honored); `@` symbol marks a secret channel |
| `LIST [filters]` | | channel directory; `+s` channels hidden from non-members; `SAFELIST`; ELIST filters: `>n`/`<n` member counts, `C<n`/`C>n` creation age, `T<n`/`T>n` topic age (minutes), name masks and `!mask` |
| `REGISTER <#chan>` | @ | register the channel to your account (founder, persisted topic/modes, auto-op) — [details](/guide/channels#channel-registration) |

## Queries

| Command | | Description |
| --- | --- | --- |
| `WHO <mask> [%fields]` | | classic (352) or WHOX (354) with field selection; mask-based and network-wide |
| `WHOIS <nick>` | | user details incl. account (330), idle (317), operator (313), secure connection (671), actual host for privileged viewers (338); works cross-server |
| `WHOWAS <nick> [count]` | | recently-departed identities (314/369); fed by disconnects and nick changes |
| `USERHOST <nick>…` | | up to 5 nicks, short form |
| `ISON <nick>…` | | presence poll |
| `MONITOR +/-/C/L/S <nicks>` | | server-side presence notifications (730/731); ≤ 100 entries; presence is **network-wide** (a nick on a linked server counts as online); with `extended-monitor`, watchers also receive AWAY/ACCOUNT/SETNAME/CHGHOST for monitored nicks |
| `WATCH [+nick\|-nick\|C\|L\|S]…` | | the legacy spelling of MONITOR (600–607); shares the same watch list |
| `SILENCE [+mask\|-mask]` | | personal server-side ignore list (≤ 32 masks, `SILENCE=32`): private messages from a matching mask are dropped, local or remote |
| `MAP` | | the network as a tree of servers (015/017) |
| `LUSERS` | | population statistics incl. operators (252) and unknown connections (253) |
| `MOTD` | | message of the day |
| `VERSION` / `TIME` / `ADMIN` / `INFO` | | server metadata |
| `LINKS` | | the servers of the network with uplinks and hop counts (364/365) |
| `STATS u\|o\|k\|d` | | uptime is public; operator/ban reports require the oper flag |
| `HELP [topic]` | | command index, or usage for one command (704/705/706) |

## History & metadata

| Command | | Description |
| --- | --- | --- |
| `CHATHISTORY <sub> …` | | `LATEST` / `BEFORE` / `AFTER` / `AROUND` / `BETWEEN` / `TARGETS` — full grammar in the [CHATHISTORY reference](/reference/chathistory); with `draft/event-playback`, JOIN/PART/QUIT/NICK/KICK/TOPIC/MODE events are replayed too |
| `METADATA <target> GET\|LIST\|SET\|CLEAR\|SUB\|UNSUB\|SUBS …` | | `draft/metadata-2` key-value store on users and channels; ≤ 20 keys, key ≤ 32 chars, value ≤ 300 chars; channel keys are op-gated (`FAIL METADATA KEY_NO_PERMISSION`). `SUB`/`UNSUB`/`SUBS` (770/771/772) manage key subscriptions — a subscriber gets a `METADATA` event whenever a visible user or channel changes that key |
| `MARKREAD <target> [timestamp=…]` | | get or set your read marker (`draft/read-marker`); markers only move forward and sync to every connection of the same account |
| `REDACT <target> <msgid> [:<reason>]` | | delete a sent message from history (`draft/message-redaction`); channel ops may redact anything, everyone else only their own; federated over S2S |
| `RENAME <#old> <#new> [:<reason>]` | | rename a channel in place (`draft/channel-rename`, op-only); members, modes, topic, history, registration and read markers follow; non-supporting members get a PART/JOIN resync |

## Accounts

| Command | | Description |
| --- | --- | --- |
| `REGISTER <acct\|*> <email> <password>` | | self-register an account (`draft/account-registration`); persisted when `[persistence]` is on — [details](/guide/accounts#self-registration-register) |
| `OPER <name> <password>` | | authenticate as an IRC operator; the block's optional `hosts` list gates by hostmask/IP (491), then the password is checked (464/381) |

*(Both spellings of `REGISTER` — channel and account — are distinguished by
the first parameter: `#`-prefixed = channel registration.)*

## Operator commands

All require the oper flag; without it: `481 ERR_NOPRIVILEGES`. Guide:
[Operators & Moderation](/guide/operators).

| Command | Description |
| --- | --- |
| `KILL <nick>[,<nick>] :<reason>` | forcibly disconnect users — local or on any linked server; server names are refused (483) |
| `KLINE <mask> :<reason>` / `UNKLINE <mask>` | host-mask ban at registration (+ kills current matches), this server only |
| `GLINE <mask> :<reason>` / `UNGLINE <mask>` | network-wide ban: applied like a K-Line on every linked server |
| `DLINE <ip-mask> :<reason>` / `UNDLINE <ip-mask>` | IP ban at TCP accept — cheapest rejection, pre-TLS |
| `CHGHOST <nick> <user> <host>` | change a user's displayed user@host (`chghost` cap broadcast; propagated over S2S) |
| `WALLOPS :<text>` | broadcast to all `+w` users, network-wide |
| `GLOBOPS :<text>` (`OPERWALL`) | the same broadcast, marked `[GLOBOPS]` |
| `REHASH` | hot-reload accounts, operators, bans, MOTD, connection password (382) |
| `DIE` | graceful shutdown of this server (announced via WALLOPS) |

## Standard replies (`FAIL`)

With the `standard-replies` capability, errors outside the numeric system
arrive as `FAIL <command> <code> [context] :<description>`; without the
cap, the same content falls back to a server `NOTICE`. Codes ferrixd emits:

| Command | Codes |
| --- | --- |
| `BATCH` | `MULTILINE_INVALID_TARGET`, `MULTILINE_MAX_LINES`, `MULTILINE_MAX_BYTES` |
| `CHATHISTORY` | `NEED_MORE_PARAMS`, `INVALID_TARGET`, `INVALID_PARAMS` |
| `JOIN` | `JOIN_BLOCKED` (plugin veto) |
| `PRIVMSG`/`NOTICE` | `MSG_BLOCKED` (plugin veto) |
| `METADATA` | `INVALID_PARAMS`, `INVALID_TARGET`, `KEY_NOT_SET`, `KEY_INVALID`, `VALUE_INVALID`, `KEY_NO_PERMISSION`, `TOO_MANY_SUBS` |
| `MARKREAD` | `NEED_MORE_PARAMS`, `INVALID_PARAMS` |
| `REDACT` | `NEED_MORE_PARAMS`, `INVALID_TARGET`, `UNKNOWN_MSGID`, `REDACT_FORBIDDEN` |
| `RENAME` | `NEED_MORE_PARAMS`, `CANNOT_RENAME`, `CHANNEL_NAME_IN_USE` |
| `REGISTER` | `NEED_MORE_PARAMS`, `BAD_ACCOUNT_NAME`, `ACCOUNT_EXISTS`, `TEMPORARILY_UNAVAILABLE`, `ACCOUNT_REQUIRED`, `INVALID_CHANNEL`, `CHANOPRIVSNEEDED`, `ALREADY_REGISTERED` |

## Not implemented

By design (config-driven federation, no legacy surface): `CONNECT`,
`SQUIT` (as a client command), `TRACE`, `WEBIRC`, `RESTART` (use your
service manager). S2S links are managed entirely through `[[links]]` in
the [configuration](/reference/config#links-optional-repeatable). The
obsolete RFC verbs `SUMMON`, `USERS`, `SERVICE`, `SERVLIST` and `SQUERY`
are also absent.
