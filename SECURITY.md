# Security Policy

## Supported versions

| Version | Supported                  |
| ------- | -------------------------- |
| 1.x     | ✅ security fixes           |
| < 1.0   | ❌ pre-release, unsupported |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/josunlp/ferrixd/security/advisories/new)
(Security → Report a vulnerability). Include:

- the affected version (`ferrixd --version`) and configuration (redact secrets);
- what an attacker can achieve, and what access they need to start;
- a reproduction — a packet trace, a config, or a short script is ideal.

You will get an acknowledgement within **72 hours** and an assessment within
**7 days**. Fixes ship as a patch release with an advisory crediting you,
unless you prefer otherwise.

## What is in scope

The daemon as configured by a reasonable operator, in particular:

- remote crashes, hangs, or unbounded resource growth from **unauthenticated**
  network input (a client or a peer server);
- authentication or authorization bypass — SASL, `OPER`, channel privileges,
  bans (K/D/G-lines), or the S2S origin checks;
- leaks of another user's private data (message contents, real IP behind a
  cloak, secret channel membership);
- protocol-level flaws that let one server on a link forge state for a server
  it does not route.

## What is not in scope

- Attacks that require an already-trusted operator (`OPER`) — an oper can
  legitimately kill users, ban, and shut the server down.
- Denial of service from a peer you deliberately linked: S2S peers are trusted
  by design (mutual TLS + pinned fingerprint + shared token), and `WALLOPS`,
  `KILL`, and network bans are accepted from them network-wide.
- Running the plaintext listener on a public interface after explicitly setting
  `allow_plain_nonlocal = true` — that is a documented foot-gun, and the server
  refuses it otherwise.
- Resource exhaustion that the documented limits are meant to bound, when those
  limits have been raised past their defaults.

## Hardening

The [Security Model](https://josunlp.github.io/ferrixd/internals/security)
documents the trust boundaries, the crypto choices, and the DoS controls, and
[Limits](https://josunlp.github.io/ferrixd/reference/limits) lists every
bound the server enforces.
