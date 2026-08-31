//! IRCv3 capability negotiation.
//!
//! A capability is a feature the client opts into with `CAP REQ`. We model the
//! supported set as a compact bitset ([`CapSet`]) stored lock-free on each
//! [`crate::state::ClientEntry`] (an `AtomicU32`), so the broadcast hot path can
//! read a recipient's caps without taking a lock.

/// SASL mechanisms advertised in `CAP LS` and accepted by `AUTHENTICATE`.
pub const SASL_MECHANISMS: &[&str] = &["PLAIN", "EXTERNAL", "SCRAM-SHA-256"];

/// `draft/multiline` limits, advertised as the capability's value and enforced
/// when a batch is assembled (a client cannot honour a limit it is not told).
pub const MULTILINE_MAX_BYTES: usize = 4096;
/// Maximum lines in one `draft/multiline` batch.
pub const MULTILINE_MAX_LINES: usize = 100;

/// A single capability. The discriminant doubles as the bit index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    Sasl,
    MessageTags,
    ServerTime,
    EchoMessage,
    AccountTag,
    AwayNotify,
    ExtendedJoin,
    ChgHost,
    SetName,
    MultiPrefix,
    UserhostInNames,
    CapNotify,
    InviteNotify,
    Batch,
    ChatHistory,
    StandardReplies,
    Metadata,
    LabeledResponse,
    Multiline,
    AccountRegistration,
    AccountNotify,
    ExtendedMonitor,
    ReadMarker,
    EventPlayback,
    MessageRedaction,
    ChannelRename,
    NoImplicitNames,
    PreAway,
    ExtendedIsupport,
}

impl Cap {
    /// Every capability we support, in advertisement order.
    pub const ALL: &'static [Cap] = &[
        Cap::Sasl,
        Cap::MessageTags,
        Cap::ServerTime,
        Cap::EchoMessage,
        Cap::AccountTag,
        Cap::AwayNotify,
        Cap::ExtendedJoin,
        Cap::ChgHost,
        Cap::SetName,
        Cap::MultiPrefix,
        Cap::UserhostInNames,
        Cap::CapNotify,
        Cap::InviteNotify,
        Cap::Batch,
        Cap::ChatHistory,
        Cap::StandardReplies,
        Cap::Metadata,
        Cap::LabeledResponse,
        Cap::Multiline,
        Cap::AccountRegistration,
        Cap::AccountNotify,
        Cap::ExtendedMonitor,
        Cap::ReadMarker,
        Cap::EventPlayback,
        Cap::MessageRedaction,
        Cap::ChannelRename,
        Cap::NoImplicitNames,
        Cap::PreAway,
        Cap::ExtendedIsupport,
    ];

    /// This capability's bit in a [`CapSet`].
    #[must_use]
    pub const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// The capability's wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Cap::Sasl => "sasl",
            Cap::MessageTags => "message-tags",
            Cap::ServerTime => "server-time",
            Cap::EchoMessage => "echo-message",
            Cap::AccountTag => "account-tag",
            Cap::AwayNotify => "away-notify",
            Cap::ExtendedJoin => "extended-join",
            Cap::ChgHost => "chghost",
            Cap::SetName => "setname",
            Cap::MultiPrefix => "multi-prefix",
            Cap::UserhostInNames => "userhost-in-names",
            Cap::CapNotify => "cap-notify",
            Cap::InviteNotify => "invite-notify",
            Cap::Batch => "batch",
            Cap::ChatHistory => "draft/chathistory",
            Cap::StandardReplies => "standard-replies",
            Cap::Metadata => "draft/metadata-2",
            Cap::LabeledResponse => "labeled-response",
            Cap::Multiline => "draft/multiline",
            Cap::AccountRegistration => "draft/account-registration",
            Cap::AccountNotify => "account-notify",
            Cap::ExtendedMonitor => "extended-monitor",
            Cap::ReadMarker => "draft/read-marker",
            Cap::EventPlayback => "draft/event-playback",
            Cap::MessageRedaction => "draft/message-redaction",
            Cap::ChannelRename => "draft/channel-rename",
            Cap::NoImplicitNames => "no-implicit-names",
            Cap::PreAway => "draft/pre-away",
            Cap::ExtendedIsupport => "draft/extended-isupport",
        }
    }

    /// Resolve a wire name to a capability.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Cap> {
        Cap::ALL.iter().copied().find(|c| c.name() == name)
    }

    /// The `CAP LS` advertisement token, e.g. `server-time` or
    /// `sasl=PLAIN,EXTERNAL`.
    #[must_use]
    pub fn ls_token(self) -> String {
        match self {
            Cap::Sasl => format!("sasl={}", SASL_MECHANISMS.join(",")),
            Cap::Multiline => {
                format!(
                    "draft/multiline=max-bytes={MULTILINE_MAX_BYTES},max-lines={MULTILINE_MAX_LINES}"
                )
            }
            // The registration policy a client must satisfy (IRCv3
            // draft/account-registration): no e-mail, and any account name.
            Cap::AccountRegistration => {
                "draft/account-registration=before-connect,custom-account-name".to_owned()
            }
            other => other.name().to_owned(),
        }
    }
}

/// A set of capabilities, one bit each.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapSet(u32);

impl CapSet {
    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Reconstruct from raw bits (as stored in the atomic).
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw bits (for storing in the atomic).
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Does the set contain `cap`?
    #[must_use]
    pub const fn has(self, cap: Cap) -> bool {
        self.0 & cap.bit() != 0
    }

    /// Add a capability.
    pub fn insert(&mut self, cap: Cap) {
        self.0 |= cap.bit();
    }

    /// Remove a capability.
    pub fn remove(&mut self, cap: Cap) {
        self.0 &= !cap.bit();
    }

    /// Keep only the bits in `mask`.
    #[must_use]
    pub const fn masked(self, mask: u32) -> Self {
        Self(self.0 & mask)
    }
}

/// The full `CAP LS` capability list. `sts` (strict transport security) is a
/// per-connection advertisement — its value differs between plaintext and TLS
/// connections and it is deliberately NOT a [`Cap`] (clients must not `REQ`
/// it) — so the caller passes the ready-made token, if any.
#[must_use]
pub fn ls_line(sts_token: Option<&str>) -> String {
    let mut tokens: Vec<String> = Cap::ALL.iter().map(|c| c.ls_token()).collect();
    if let Some(sts) = sts_token {
        tokens.push(sts.to_owned());
    }
    tokens.join(" ")
}

/// The names of currently-enabled caps, space-separated (for `CAP LIST`).
#[must_use]
pub fn list_line(caps: CapSet) -> String {
    Cap::ALL
        .iter()
        .copied()
        .filter(|c| caps.has(*c))
        .map(Cap::name)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Outcome of parsing a `CAP REQ` argument.
#[derive(Debug, PartialEq, Eq)]
pub enum ReqParse {
    /// All tokens are known; apply these `(cap, enable)` changes atomically.
    Ok(Vec<(Cap, bool)>),
    /// At least one token was unknown; the whole request must be NAKed.
    Unknown,
}

/// Parse a `CAP REQ` token list (space-separated, each optionally `-`-prefixed
/// to disable). Any unknown token invalidates the whole request.
#[must_use]
pub fn parse_req(arg: &str) -> ReqParse {
    let mut changes = Vec::new();
    for token in arg.split_whitespace() {
        let (enable, name) = match token.strip_prefix('-') {
            Some(rest) => (false, rest),
            None => (true, token),
        };
        match Cap::from_name(name) {
            Some(cap) => changes.push((cap, enable)),
            None => return ReqParse::Unknown,
        }
    }
    ReqParse::Ok(changes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_unique() {
        let mut seen = 0u32;
        for cap in Cap::ALL {
            assert_eq!(seen & cap.bit(), 0, "duplicate bit for {}", cap.name());
            seen |= cap.bit();
        }
    }

    #[test]
    fn set_insert_remove_has() {
        let mut caps = CapSet::empty();
        assert!(!caps.has(Cap::ServerTime));
        caps.insert(Cap::ServerTime);
        assert!(caps.has(Cap::ServerTime));
        caps.remove(Cap::ServerTime);
        assert!(!caps.has(Cap::ServerTime));
    }

    #[test]
    fn ls_line_includes_sasl_mechanisms() {
        let line = ls_line(None);
        assert!(line.contains("sasl=PLAIN,EXTERNAL"));
        assert!(line.contains("server-time"));
        assert!(line.contains("echo-message"));
        assert!(!line.contains("sts="));
    }

    #[test]
    fn ls_line_appends_sts_token() {
        let line = ls_line(Some("sts=port=6697"));
        assert!(line.ends_with("sts=port=6697"));
        // sts must not be REQable.
        assert_eq!(parse_req("sts"), ReqParse::Unknown);
    }

    #[test]
    fn parse_req_known_and_unknown() {
        assert_eq!(
            parse_req("server-time -echo-message"),
            ReqParse::Ok(vec![(Cap::ServerTime, true), (Cap::EchoMessage, false)])
        );
        assert_eq!(parse_req("server-time bogus"), ReqParse::Unknown);
    }
}
