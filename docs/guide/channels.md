# Channels

Channels in ferrixd behave the way IRC veterans expect — `#`-prefixed,
op/voice prefixes, the classic mode set — with two modern additions:
**account extbans** and **channel registration** with persistence.

## Basics

```
JOIN #forge
TOPIC #forge :welcome to the forge
NAMES #forge
PART #forge :goodbye
```

New channels are created on first join; the first member gets `+o`. Channels
default to `+nt` (no external messages, topic locked to ops). A client can
be in at most `max_channels` channels (default 50; opers exempt).

Names are case-folded with the network's `casemapping` (`ascii` or
`rfc1459`), max length 50.

## Channel modes

Set and query with `MODE`:

```
MODE #forge +m           # moderated
MODE #forge +k hunter2   # key (password) required to join
MODE #forge +l 100       # member limit
MODE #forge +o alice     # give ops
MODE #forge -o+v alice   # …swap for voice
```

| Mode | Type | Meaning |
| --- | --- | --- |
| `o` | member | channel operator (`@` prefix) |
| `v` | member | voice — may speak under `+m` (`+` prefix) |
| `i` | flag | invite-only — join requires `INVITE` or a `+I` match |
| `m` | flag | moderated — only `+o`/`+v` may speak |
| `n` | flag | no external messages (default on) |
| `s` | flag | secret — hidden from `LIST` and `WHOIS` of non-members |
| `t` | flag | topic settable by ops only (default on) |
| `k` | param | join key |
| `l` | param | member limit |
| `b` | list | ban list |
| `e` | list | ban exceptions |
| `I` | list | invite exceptions (bypass `+i`) |

Up to 6 mode changes are accepted per `MODE` command (`MODES=6`). The
machine-readable summary clients get is
`CHANMODES=beI,k,l,imnst` — see [Modes & ISUPPORT](/reference/modes).

## Bans, exceptions, invite lists

The three list modes share syntax and a 100-entries-per-list cap:

```
MODE #forge +b *!*@*.spam.example     # ban a host mask
MODE #forge +e *!*@friend.example     # …but exempt this one
MODE #forge +I *!*@*.trusted.example  # may join through +i
MODE #forge +b                        # view the ban list (367/368)
```

Masks are `nick!user@host` globs. Bare words are normalized: a bare host
becomes `*!*@host`, a bare nick becomes `nick!*@*`.

### Account extbans: `~a:`

A mask starting with `~a:` matches the user's **logged-in account** instead
of their mask:

```
MODE #forge +b ~a:mallory      # ban the account, not the hostname
MODE #forge +e ~a:alice        # exempt alice regardless of where she connects
MODE #forge +I ~a:staff*       # any account matching staff* joins through +i
```

Account extbans survive IP changes, cloaks, and nick changes — they follow
the identity. They work in all three lists (`+b`/`+e`/`+I`). The support is
advertised to clients as `EXTBAN=~,a` in `RPL_ISUPPORT` (005).

### Enforcement

- Bans are enforced on `JOIN` (banned users can't join unless a `+e`
  exception matches).
- A user matching `+I` may join an invite-only channel without an `INVITE`.
- `INVITE` from a channel op bypasses `+i` for the invitee; with the
  `invite-notify` capability, other ops see who invited whom.

## Moderation inside a channel

```
KICK #forge mallory :Enough
MODE #forge +b ~a:mallory
TOPIC #forge :New topic
```

`KICK`, topic changes under `+t`, mode changes, and `INVITE` into a `+i`
channel all require channel-operator status. Everything propagates across
[federation links](/guide/federation) with the acting user attributed.

## Channel registration

A logged-in channel operator can register the channel to their account:

```
REGISTER #forge
```

Registration records the caller's account as the channel **founder** and —
with `[persistence]` enabled — persists the channel's topic, modes, key and
limit to SQLite. From then on:

- the channel's topic and modes are **restored after a server restart**,
  even if the channel was empty;
- the founder is **auto-opped** on join — identity-based, via their account.

Requirements: you must be logged in (any [SASL mechanism](/guide/accounts))
and hold `+o` in the channel. Failure cases arrive as `standard-replies`
(`FAIL REGISTER ACCOUNT_REQUIRED`, `FAIL REGISTER CHANOPRIVSNEEDED`, …).

::: tip Registration + extbans = services, without services
Founder auto-op, account bans (`~a:`), and persisted modes cover most of
what ChanServ historically did — with no second daemon, no services split,
and no password-over-PRIVMSG folklore.
:::

## Listing and visibility

- `LIST` shows channels with their member counts and topics; `+s` channels
  are hidden unless you're a member. `SAFELIST` is advertised — the server
  won't flood you off for listing.
- `NAMES` shows prefixes; with `multi-prefix`, all of them
  (`@+nick`); with `userhost-in-names`, full `nick!user@host`.
- `WHO #forge` supports classic replies and `WHOX` (`WHO #forge %tcuihsnfar`)
  for field-selected queries, network-wide.

## History

Channels get server-side history automatically — `CHATHISTORY LATEST #forge
* 50` replays into a batch, membership required. Retention and persistence
are the operator's call: [Message History](/guide/history).
