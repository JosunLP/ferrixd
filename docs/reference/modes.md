# Modes & ISUPPORT

## Channel modes

Advertised as `CHANMODES=beI,k,l,imnst` (list, param-when-set-and-unset,
param-when-set, flags). Up to **6** mode changes per `MODE` command
(`MODES=6`).

### Member modes (`PREFIX=(ov)@+`)

| Mode | Prefix | Meaning |
| --- | --- | --- |
| `o` | `@` | channel operator — topic under `+t`, modes, `KICK`, `INVITE` under `+i`, channel `METADATA` |
| `v` | `+` | voice — may speak under `+m` |

### Flag modes

| Mode | Default | Meaning |
| --- | --- | --- |
| `i` | off | invite-only; join requires `INVITE` or matching `+I` |
| `m` | off | moderated; only `+o`/`+v` may speak |
| `n` | **on** | no external messages (must be a member to send) |
| `s` | off | secret; hidden from `LIST` for non-members |
| `t` | **on** | topic changes restricted to channel operators |

New channels start `+nt`.

### Parameter modes

| Mode | Parameter | Meaning |
| --- | --- | --- |
| `k` | key | join requires `JOIN #chan <key>` |
| `l` | limit | join refused once the member count reaches the limit |

### List modes

Each list holds at most **100** entries (`MAXLIST=b:100,e:100,I:100`);
querying without a parameter returns the list (`367/368`, `348/349`,
`346/347`).

| Mode | List | Effect |
| --- | --- | --- |
| `b` | bans | matching users cannot join |
| `e` | ban exceptions | overrides `+b` |
| `I` | invite exceptions | may join through `+i` without an `INVITE` |

**Mask forms** accepted in all three lists:

- `nick!user@host` glob (`*`, `?`) — bare hosts normalize to `*!*@host`,
  bare nicks to `nick!*@*`;
- `~a:<glob>` — **account extban**: matches the sender's logged-in account
  name instead of the hostmask. [Guide](/guide/channels#account-extbans-a).

## User modes

| Mode | Set by | Meaning |
| --- | --- | --- |
| `i` | user | invisible (hidden from `WHO`/`NAMES` scans by non-common-channel users) |
| `w` | user | receives `WALLOPS` |
| `B` | user | bot (IRCv3 bot-mode): shown in `WHOIS` (`RPL_WHOISBOT`, 335) and `WHO` flags, and tags the bot's messages with a bare `@bot` — advertised as `BOT=B` |
| `o` | server | IRC operator — granted only by `OPER`; a user may remove it (`-o`) but never set it |

## ISUPPORT (005) tokens

What ferrixd advertises at registration, and what each token promises:

| Token | Value | Meaning |
| --- | --- | --- |
| `NETWORK` | from config | network name |
| `CASEMAPPING` | `ascii` \| `rfc1459` | how nicks/channels case-fold |
| `CHANTYPES` | `#` | only `#` channels exist |
| `CHANMODES` | `beI,k,l,imnst` | mode classes as above |
| `PREFIX` | `(ov)@+` | member modes and their prefixes |
| `MODES` | `6` | max mode changes per `MODE` |
| `EXCEPTS` | `e` | ban exceptions supported |
| `INVEX` | `I` | invite exceptions supported |
| `MAXLIST` | `b:100,e:100,I:100` | list-mode caps |
| `NICKLEN` | `30` | max nick length |
| `CHANNELLEN` | `50` | max channel-name length |
| `TOPICLEN` | `390` | advertised topic length |
| `KICKLEN` | `300` | advertised kick-reason length |
| `AWAYLEN` | `200` | advertised away-reason length |
| `CHANLIMIT` | `#:<max_channels>` | per-client channel cap (config) |
| `MAXCHANNELS` | `<max_channels>` | legacy spelling of the same |
| `TARGMAX` | `PRIVMSG:1,NOTICE:1` | one target per message command |
| `MONITOR` | `100` | MONITOR list capacity |
| `WHOX` | — | `WHO` field selection (354) supported |
| `CHATHISTORY` | `100` | max messages per CHATHISTORY request |
| `MSGREFTYPES` | `timestamp,msgid` | selector types CHATHISTORY accepts |
| `SAFELIST` | — | `LIST` won't get you flooded off |
| `ELIST` | `CMNTU` | `LIST` filters: creation age, masks, negated masks, topic age, user counts |
| `KNOCK` | — | `KNOCK` on invite-only channels supported |
| `STATUSMSG` | `@+` | `PRIVMSG @#chan` / `+#chan` reach only prefixed members |
| `UTF8ONLY` | — | the server expects UTF-8 |
| `BOT` | `B` | user mode letter that marks a bot (IRCv3 bot-mode) |
| `draft/ICON` | from config | network icon URL, when `server.icon` is set (IRCv3 `draft/network-icon`) |

::: info Advertised vs. enforced
`TOPICLEN`, `KICKLEN`, and `AWAYLEN` are advisory values for clients; the
hard limit that is always enforced is the 512-byte message body budget on
the wire. Nick and channel lengths *are* enforced exactly as advertised.
:::
