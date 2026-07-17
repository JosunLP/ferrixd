//! End-to-end integration tests for the IRC server.
//!
//! Clients are driven over in-memory duplex streams (and one real TLS stream),
//! exercising registration, channels, messaging, and error paths against the
//! actual `serve` loop and shared state.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use ferrix_protocol::Limits;
use ferrixd::account::AccountStore;
use ferrixd::casemap::CaseMapping;
use ferrixd::connection::ConnContext;
use ferrixd::state::{Server, ServerInfo};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

/// A test context seeded with one password account (PLAIN + SCRAM credentials).
fn test_context_with_account(name: &str, password: &str) -> ConnContext {
    let ctx = test_context();
    ctx.server.accounts.set_password(name, password).unwrap();
    ctx
}

/// A test context seeded with one IRC-operator credential.
fn test_context_with_oper(name: &str, password: &str) -> ConnContext {
    let ctx = test_context();
    let hash = AccountStore::hash_password(password, name).unwrap();
    ctx.server.opers.upsert_password(name, hash);
    ctx
}

/// base64-encode a SASL PLAIN payload `\0<authcid>\0<password>`.
fn plain_payload(authcid: &str, password: &str) -> String {
    let raw = format!("\0{authcid}\0{password}");
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
}

/// A fresh, isolated server context for one test.
fn test_context() -> ConnContext {
    let server = Server::new(ServerInfo {
        name: "irc.test".to_owned(),
        sid: "42T".to_owned(),
        network: "TestNet".to_owned(),
        icon: None,
        version: "ferrixd-test".to_owned(),
        created: "2026-07-08 00:00:00 UTC".to_owned(),
        casemapping: CaseMapping::Ascii,
        motd: Vec::new(),
        history_len: 500,
        history_max_targets: 50_000,
        max_channels: 50,
        cloak_key: None,
        sts: None,
    });
    ConnContext {
        server,
        limits: Limits::default(),
        max_line: 8704,
        registration_timeout: Duration::from_secs(5),
        max_clients_per_ip: 100,
        sendq_lines: 1024,
        recv_burst: 200,
        recv_rate: 200,
        ping_interval: Duration::from_secs(120),
    }
}

/// Read lines until one contains `needle`, returning everything read.
async fn read_until<R: AsyncBufReadExt + Unpin>(reader: &mut R, needle: &str) -> String {
    let mut acc = String::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}; got:\n{acc}"))
            .expect("read error");
        assert!(n != 0, "EOF before finding {needle:?}; got:\n{acc}");
        acc.push_str(&line);
        if line.contains(needle) {
            return acc;
        }
    }
}

/// A test client connected to the server over a duplex stream.
struct Conn {
    writer: WriteHalf<DuplexStream>,
    reader: BufReader<ReadHalf<DuplexStream>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Conn {
    fn spawn(ctx: ConnContext, port: u16) -> Self {
        Self::spawn_with(ctx, port, false)
    }

    /// Like [`Conn::spawn`], with an explicit TLS-secured flag (sts tests).
    fn spawn_with(ctx: ConnContext, port: u16, secure: bool) -> Self {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = format!("127.0.0.1:{port}").parse().unwrap();
        let task = tokio::spawn(ferrixd::connection::serve(server, peer, ctx, None, secure));
        let (rd, writer) = tokio::io::split(client);
        Self {
            writer,
            reader: BufReader::new(rd),
            _task: task,
        }
    }

    async fn send(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    async fn expect(&mut self, needle: &str) -> String {
        read_until(&mut self.reader, needle).await
    }

    /// Complete registration and wait for the welcome numeric.
    async fn register(&mut self, nick: &str) -> String {
        self.send(&format!("NICK {nick}")).await;
        self.send(&format!("USER {nick} 0 * :Real {nick}")).await;
        self.expect("001").await
    }

    /// Register while negotiating the given space-separated capabilities.
    async fn register_caps(&mut self, nick: &str, caps: &str) -> String {
        self.send(&format!("CAP REQ :{caps}")).await;
        self.expect("ACK").await;
        self.send(&format!("NICK {nick}")).await;
        self.send(&format!("USER {nick} 0 * :Real {nick}")).await;
        self.send("CAP END").await;
        self.expect("001").await
    }
}

#[tokio::test]
async fn registration_yields_welcome_burst() {
    let mut alice = Conn::spawn(test_context(), 1001);
    let welcome = alice.register("alice").await;
    assert!(welcome.contains("001"), "no RPL_WELCOME: {welcome}");
    assert!(
        welcome.contains("Welcome to the TestNet Network, alice!~alice@127.0.0.1"),
        "unexpected welcome text: {welcome}"
    );
    // The rest of the burst (004 MYINFO, 005 ISUPPORT — now several lines) follows.
    let isupport = alice.expect("CASEMAPPING=ascii").await;
    assert!(
        isupport.contains("CASEMAPPING=ascii"),
        "no ISUPPORT: {isupport}"
    );
}

#[tokio::test]
async fn two_clients_can_chat_in_a_channel() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 2001);
    let mut bob = Conn::spawn(ctx.clone(), 2002);
    alice.register("alice").await;
    bob.register("bob").await;

    // Alice creates the channel (becomes op) and sees her own JOIN + NAMES.
    alice.send("JOIN #room").await;
    let names = alice.expect("End of /NAMES").await;
    assert!(names.contains("@alice"), "creator should be op: {names}");

    // Bob joins; Alice must observe Bob's JOIN.
    bob.send("JOIN #room").await;
    bob.expect("End of /NAMES").await;
    let seen = alice.expect("JOIN").await;
    assert!(seen.contains("bob"), "alice did not see bob join: {seen}");

    // Alice speaks; Bob receives it, Alice does not get an echo.
    alice.send("PRIVMSG #room :hello bob").await;
    let msg = bob.expect("hello bob").await;
    assert!(msg.contains("PRIVMSG #room"), "bad delivery: {msg}");
    assert!(
        msg.contains(":alice!~alice@127.0.0.1"),
        "missing source prefix: {msg}"
    );
}

#[tokio::test]
async fn part_and_quit_are_broadcast() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 3001);
    let mut bob = Conn::spawn(ctx.clone(), 3002);
    alice.register("alice").await;
    bob.register("bob").await;
    alice.send("JOIN #room").await;
    alice.expect("End of /NAMES").await;
    bob.send("JOIN #room").await;
    bob.expect("End of /NAMES").await;
    alice.expect("JOIN").await; // bob's join

    // Bob parts; Alice sees the PART.
    bob.send("PART #room :bye").await;
    let part = alice.expect("PART").await;
    assert!(part.contains("bob"), "no PART broadcast: {part}");

    // Bob rejoins then quits; Alice sees the QUIT.
    bob.send("JOIN #room").await;
    alice.expect("JOIN").await;
    bob.send("QUIT :leaving").await;
    let quit = alice.expect("QUIT").await;
    assert!(quit.contains("bob"), "no QUIT broadcast: {quit}");
    assert!(quit.contains("leaving"), "quit reason missing: {quit}");
}

#[tokio::test]
async fn duplicate_nick_is_refused() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 4001);
    alice.register("alice").await;

    let mut clash = Conn::spawn(ctx.clone(), 4002);
    clash.send("NICK alice").await;
    clash.send("USER x 0 * :X").await;
    let err = clash.expect("433").await;
    assert!(err.contains("alice"), "expected ERR_NICKNAMEINUSE: {err}");
}

#[tokio::test]
async fn channel_op_can_set_topic_but_others_cannot() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 5001);
    let mut bob = Conn::spawn(ctx.clone(), 5002);
    alice.register("alice").await;
    bob.register("bob").await;
    alice.send("JOIN #room").await;
    alice.expect("End of /NAMES").await;
    bob.send("JOIN #room").await;
    bob.expect("End of /NAMES").await;
    alice.expect("JOIN").await;

    // Alice (op) sets the topic; both see the TOPIC broadcast.
    alice.send("TOPIC #room :welcome all").await;
    let t = bob.expect("TOPIC").await;
    assert!(t.contains("welcome all"), "topic not broadcast: {t}");

    // Bob (not op, +t default) is refused.
    bob.send("TOPIC #room :hijack").await;
    let denied = bob.expect("482").await;
    assert!(
        denied.contains("#room"),
        "expected ERR_CHANOPRIVSNEEDED: {denied}"
    );
}

#[tokio::test]
async fn malformed_line_does_not_drop_connection() {
    let mut alice = Conn::spawn(test_context(), 6001);
    alice.register("alice").await;
    alice.send("@@@garbage nonsense").await;
    alice.send("PING :still-here").await;
    let pong = alice.expect("PONG").await;
    assert!(
        pong.contains("still-here"),
        "connection died after garbage: {pong}"
    );
}

#[tokio::test]
async fn tls_registration_end_to_end() {
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    let tls_config = ferrixd::tls::build_server_config(&ferrixd::config::TlsConfig {
        cert: None,
        key: None,
        self_signed_dev: true,
        dev_hostnames: vec!["localhost".to_owned()],
    })
    .expect("server TLS config");
    // run_tls takes the hot-swappable holder (REHASH cert rotation).
    let shared_tls = ferrixd::tls::SharedServerTls::new(tls_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = test_context();
    tokio::spawn(ferrixd::listener::run_tls(
        listener,
        shared_tls,
        ctx,
        Duration::from_secs(5),
    ));

    let connector = TlsConnector::from(Arc::new(danger::client_config()));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(domain, tcp).await.expect("handshake");
    let (rd, mut wr) = tokio::io::split(tls);
    let mut reader = BufReader::new(rd);

    wr.write_all(b"NICK secure\r\nUSER secure 0 * :Sec\r\n")
        .await
        .unwrap();
    let welcome = read_until(&mut reader, "001").await;
    assert!(welcome.contains("secure"), "no welcome over TLS: {welcome}");
}

#[tokio::test]
async fn cap_negotiation_gates_registration() {
    let mut c = Conn::spawn(test_context(), 7001);
    c.send("CAP LS 302").await;
    let ls = c.expect("LS").await;
    assert!(ls.contains("sasl=PLAIN,EXTERNAL"), "no sasl in LS: {ls}");
    assert!(ls.contains("server-time"), "no server-time in LS: {ls}");

    c.send("CAP REQ :server-time echo-message").await;
    let ack = c.expect("ACK").await;
    assert!(ack.contains("server-time"), "REQ not ACKed: {ack}");

    // NICK+USER arrive but registration must wait for CAP END.
    c.send("NICK alice").await;
    c.send("USER alice 0 * :Alice").await;
    c.send("CAP END").await;
    let welcome = c.expect("001").await;
    assert!(
        welcome.contains("alice"),
        "no welcome after CAP END: {welcome}"
    );
}

#[tokio::test]
async fn unknown_cap_is_naked() {
    let mut c = Conn::spawn(test_context(), 7011);
    c.send("CAP REQ :server-time bogus-cap").await;
    let nak = c.expect("NAK").await;
    assert!(nak.contains("bogus-cap"), "unknown cap should NAK: {nak}");
}

#[tokio::test]
async fn server_time_and_echo_message() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 7101);
    let mut b = Conn::spawn(ctx.clone(), 7102);

    a.send("CAP REQ :server-time echo-message").await;
    a.expect("ACK").await;
    a.send("NICK alice").await;
    a.send("USER alice 0 * :A").await;
    a.send("CAP END").await;
    a.expect("001").await;

    b.register("bob").await;

    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;
    a.expect("JOIN").await; // bob joined

    a.send("PRIVMSG #r :hi").await;
    // Alice has echo-message + server-time: she gets her own message, tagged.
    let echo = a.expect("PRIVMSG").await;
    assert!(echo.contains("@time="), "no server-time on echo: {echo}");
    // Bob negotiated nothing: he gets the message without tags.
    let recv = b.expect("PRIVMSG").await;
    assert!(
        !recv.contains("@time="),
        "bob should not get server-time: {recv}"
    );
    assert!(recv.contains(":alice!"), "missing source: {recv}");
}

#[tokio::test]
async fn sasl_plain_login_then_whois_account() {
    let mut c = Conn::spawn(test_context_with_account("alice", "hunter2"), 7201);
    c.send("CAP REQ :sasl").await;
    c.expect("ACK").await;
    c.send("AUTHENTICATE PLAIN").await;
    c.expect("AUTHENTICATE +").await;
    c.send(&format!(
        "AUTHENTICATE {}",
        plain_payload("alice", "hunter2")
    ))
    .await;
    let ok = c.expect("903").await;
    assert!(ok.contains("900"), "no RPL_LOGGEDIN: {ok}");

    c.send("NICK alice").await;
    c.send("USER alice 0 * :Alice").await;
    c.send("CAP END").await;
    c.expect("001").await;

    c.send("WHOIS alice").await;
    let whois = c.expect("End of /WHOIS").await;
    assert!(whois.contains("330"), "no RPL_WHOISACCOUNT: {whois}");
}

#[tokio::test]
async fn sasl_plain_wrong_password_fails() {
    let mut c = Conn::spawn(test_context_with_account("alice", "hunter2"), 7211);
    c.send("CAP REQ :sasl").await;
    c.expect("ACK").await;
    c.send("AUTHENTICATE PLAIN").await;
    c.expect("AUTHENTICATE +").await;
    c.send(&format!("AUTHENTICATE {}", plain_payload("alice", "wrong")))
        .await;
    let fail = c.expect("904").await;
    assert!(fail.contains("904"), "expected ERR_SASLFAIL: {fail}");
}

#[tokio::test]
async fn sasl_reauthenticate_mid_session_switches_account() {
    // Two accounts on one server: alice logs in during registration, then
    // re-authenticates as bob after registration (IRCv3 SASL 3.2 reauth).
    let ctx = test_context_with_account("alice", "pw-alice");
    ctx.server.accounts.set_password("bob", "pw-bob").unwrap();
    let mut c = Conn::spawn(ctx, 7221);

    c.send("CAP REQ :sasl").await;
    c.expect("ACK").await;
    c.send("AUTHENTICATE PLAIN").await;
    c.expect("AUTHENTICATE +").await;
    c.send(&format!(
        "AUTHENTICATE {}",
        plain_payload("alice", "pw-alice")
    ))
    .await;
    c.expect("903").await;
    c.send("NICK alice").await;
    c.send("USER alice 0 * :Alice").await;
    c.send("CAP END").await;
    c.expect("001").await;

    // Mid-session: re-authenticate as bob without reconnecting.
    c.send("AUTHENTICATE PLAIN").await;
    c.expect("AUTHENTICATE +").await;
    c.send(&format!("AUTHENTICATE {}", plain_payload("bob", "pw-bob")))
        .await;
    let ok = c.expect("903").await;
    assert!(ok.contains("900"), "no RPL_LOGGEDIN on reauth: {ok}");
    assert!(ok.contains("bob"), "reauth did not report bob: {ok}");

    // WHOIS now reflects the new account.
    c.send("WHOIS alice").await;
    let whois = c.expect("End of /WHOIS").await;
    assert!(whois.contains("330"), "no RPL_WHOISACCOUNT: {whois}");
    assert!(
        whois.contains("bob"),
        "WHOIS still shows old account: {whois}"
    );
}

#[tokio::test]
async fn sasl_reauthenticate_failure_keeps_existing_login() {
    // A failed mid-session reauth must leave the original login untouched.
    let ctx = test_context_with_account("alice", "pw-alice");
    ctx.server.accounts.set_password("bob", "pw-bob").unwrap();
    let mut c = Conn::spawn(ctx, 7222);

    c.send("CAP REQ :sasl").await;
    c.expect("ACK").await;
    c.send("AUTHENTICATE PLAIN").await;
    c.expect("AUTHENTICATE +").await;
    c.send(&format!(
        "AUTHENTICATE {}",
        plain_payload("alice", "pw-alice")
    ))
    .await;
    c.expect("903").await;
    c.send("NICK alice").await;
    c.send("USER alice 0 * :Alice").await;
    c.send("CAP END").await;
    c.expect("001").await;

    // Wrong password for bob: the attempt fails.
    c.send("AUTHENTICATE PLAIN").await;
    c.expect("AUTHENTICATE +").await;
    c.send(&format!("AUTHENTICATE {}", plain_payload("bob", "wrong")))
        .await;
    c.expect("904").await;

    // The original alice login is still in effect.
    c.send("WHOIS alice").await;
    let whois = c.expect("End of /WHOIS").await;
    assert!(whois.contains("330"), "no RPL_WHOISACCOUNT: {whois}");
    // Validate the account parameter in the 330 reply line (not just presence of "alice").
    let account_line = whois
        .lines()
        .find(|line| line.contains(" 330 "))
        .expect("330 line missing");
    assert!(
        account_line.ends_with(" alice :is logged in as"),
        "account parameter is not alice: {account_line}"
    );
}

#[tokio::test]
async fn extended_join_shows_account_and_realname() {
    let ctx = test_context_with_account("alice", "pw");
    let mut a = Conn::spawn(ctx.clone(), 7301);
    a.send("CAP REQ :sasl").await;
    a.expect("ACK").await;
    a.send("AUTHENTICATE PLAIN").await;
    a.expect("AUTHENTICATE +").await;
    a.send(&format!("AUTHENTICATE {}", plain_payload("alice", "pw")))
        .await;
    a.expect("903").await;
    a.send("NICK alice").await;
    a.send("USER alice 0 * :Alice Real").await;
    a.send("CAP END").await;
    a.expect("001").await;

    let mut b = Conn::spawn(ctx.clone(), 7302);
    b.send("CAP REQ :extended-join").await;
    b.expect("ACK").await;
    b.send("NICK bob").await;
    b.send("USER bob 0 * :Bob").await;
    b.send("CAP END").await;
    b.expect("001").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;

    // Alice joins; Bob (extended-join) sees her account and realname.
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    let seen = b.expect("JOIN").await;
    assert!(
        seen.contains("alice :Alice Real"),
        "extended-join missing account/realname: {seen}"
    );
}

#[tokio::test]
async fn excess_flood_disconnects() {
    let mut ctx = test_context();
    ctx.recv_burst = 5;
    ctx.recv_rate = 1;
    let mut c = Conn::spawn(ctx, 7401);
    c.register("alice").await;

    for i in 0..40 {
        c.send(&format!("PING :{i}")).await;
    }
    let got = c.expect("Excess Flood").await;
    assert!(got.contains("Excess Flood"), "flood not throttled: {got}");
}

#[tokio::test]
async fn kick_removes_member_and_broadcasts() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 8001);
    let mut b = Conn::spawn(ctx.clone(), 8002);
    a.register("alice").await;
    b.register("bob").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;
    a.expect("JOIN").await;

    a.send("KICK #r bob :behave").await;
    let kick = b.expect("KICK").await;
    assert!(kick.contains("bob") && kick.contains("behave"), "{kick}");

    // Bob is no longer a member: a channel message is now refused (+n).
    b.send("PRIVMSG #r :hi").await;
    let denied = b.expect("404").await;
    assert!(denied.contains("404"), "bob still in channel: {denied}");
}

#[tokio::test]
async fn invite_bypasses_invite_only() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 8101);
    let mut b = Conn::spawn(ctx.clone(), 8102);
    a.register("alice").await;
    b.register("bob").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    a.send("MODE #r +i").await;
    a.expect("MODE").await;

    // Bob is refused until invited.
    b.send("JOIN #r").await;
    assert!(b.expect("473").await.contains("473"), "expected +i refusal");

    a.send("INVITE bob #r").await;
    assert!(a.expect("341").await.contains("341"), "no RPL_INVITING");
    assert!(b.expect("INVITE").await.contains("#r"), "bob got no INVITE");

    b.send("JOIN #r").await;
    assert!(
        b.expect("End of /NAMES").await.contains("bob"),
        "invited bob could not join"
    );
}

#[tokio::test]
async fn channel_ban_blocks_join() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 8201);
    let mut b = Conn::spawn(ctx.clone(), 8202);
    a.register("alice").await;
    b.register("bob").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    a.send("MODE #r +b bob!*@*").await;
    a.expect("MODE").await;

    b.send("JOIN #r").await;
    let denied = b.expect("474").await;
    assert!(denied.contains("474"), "ban not enforced: {denied}");
}

#[tokio::test]
async fn oper_can_kill_a_user() {
    let ctx = test_context_with_oper("admin", "secret");
    let mut a = Conn::spawn(ctx.clone(), 8301);
    let mut b = Conn::spawn(ctx.clone(), 8302);
    a.register("alice").await;
    b.register("bob").await;

    a.send("OPER admin secret").await;
    assert!(a.expect("381").await.contains("381"), "OPER failed");

    a.send("KILL bob :bad behaviour").await;
    let err = b.expect("ERROR").await;
    assert!(err.contains("Killed"), "bob not killed: {err}");
}

#[tokio::test]
async fn oper_kline_blocks_registration() {
    let ctx = test_context_with_oper("admin", "secret");
    let mut a = Conn::spawn(ctx.clone(), 8401);
    a.register("alice").await;
    a.send("OPER admin secret").await;
    a.expect("381").await;
    a.send("KLINE bad!*@* :no bad clients").await;
    a.expect("Added K-Line").await;

    // A new client whose mask matches cannot register.
    let mut b = Conn::spawn(ctx.clone(), 8402);
    b.send("NICK bad").await;
    b.send("USER bad 0 * :Bad").await;
    let err = b.expect("ERROR").await;
    assert!(err.contains("K-Lined"), "K-Line not enforced: {err}");
}

#[tokio::test]
async fn chathistory_latest_returns_a_batch() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9001);
    a.register("alice").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    a.send("PRIVMSG #r :first").await;
    a.send("PRIVMSG #r :second").await;
    a.send("PRIVMSG #r :third").await;

    let mut b = Conn::spawn(ctx.clone(), 9002);
    b.send("CAP REQ :batch draft/chathistory message-tags server-time")
        .await;
    b.expect("ACK").await;
    b.send("NICK bob").await;
    b.send("USER bob 0 * :Bob").await;
    b.send("CAP END").await;
    b.expect("001").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;

    b.send("CHATHISTORY LATEST #r * 10").await;
    let hist = b.expect("BATCH -").await;
    assert!(hist.contains("BATCH +"), "no batch open: {hist}");
    assert!(
        hist.contains("chathistory #r"),
        "wrong batch type/target: {hist}"
    );
    assert!(
        hist.contains("first") && hist.contains("second") && hist.contains("third"),
        "missing messages: {hist}"
    );
    assert!(hist.contains("msgid="), "no msgid tag: {hist}");
    assert!(
        hist.contains("@batch="),
        "no @batch tag on replayed messages: {hist}"
    );
}

#[tokio::test]
async fn live_message_carries_msgid() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9101);
    a.register("alice").await;
    let mut b = Conn::spawn(ctx.clone(), 9102);
    b.send("CAP REQ :message-tags").await;
    b.expect("ACK").await;
    b.send("NICK bob").await;
    b.send("USER bob 0 * :B").await;
    b.send("CAP END").await;
    b.expect("001").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;
    a.expect("JOIN").await;

    a.send("PRIVMSG #r :hi bob").await;
    let recv = b.expect("PRIVMSG").await;
    assert!(recv.contains("msgid="), "no msgid on live message: {recv}");
}

#[tokio::test]
async fn chathistory_non_member_gets_standard_reply() {
    let mut a = Conn::spawn(test_context(), 9201);
    a.send("CAP REQ :standard-replies").await;
    a.expect("ACK").await;
    a.send("NICK alice").await;
    a.send("USER alice 0 * :A").await;
    a.send("CAP END").await;
    a.expect("001").await;

    a.send("CHATHISTORY LATEST #nope * 10").await;
    let fail = a.expect("FAIL").await;
    assert!(
        fail.contains("CHATHISTORY") && fail.contains("INVALID_TARGET"),
        "expected FAIL CHATHISTORY INVALID_TARGET: {fail}"
    );
}

#[tokio::test]
async fn metadata_set_get_list_on_self() {
    let mut a = Conn::spawn(test_context(), 9301);
    a.send("CAP REQ :draft/metadata-2 standard-replies").await;
    a.expect("ACK").await;
    a.send("NICK alice").await;
    a.send("USER alice 0 * :A").await;
    a.send("CAP END").await;
    a.expect("001").await;

    a.send("METADATA * SET display-name :Alice A").await;
    let set = a.expect("761").await;
    assert!(
        set.contains("display-name") && set.contains("Alice A"),
        "SET echo: {set}"
    );

    a.send("METADATA * GET display-name").await;
    assert!(a.expect("761").await.contains("Alice A"), "GET failed");

    a.send("METADATA * LIST").await;
    let list = a.expect("762").await;
    assert!(list.contains("display-name"), "LIST missing key: {list}");
}

#[tokio::test]
async fn metadata_on_channel_requires_op() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9401);
    let mut b = Conn::spawn(ctx.clone(), 9402);
    a.register("alice").await; // creates #r as op
    b.send("CAP REQ :draft/metadata-2 standard-replies").await;
    b.expect("ACK").await;
    b.send("NICK bob").await;
    b.send("USER bob 0 * :B").await;
    b.send("CAP END").await;
    b.expect("001").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;

    // Bob (not op) cannot set channel metadata.
    b.send("METADATA #r SET url :http://x").await;
    let denied = b.expect("FAIL").await;
    assert!(
        denied.contains("KEY_NO_PERMISSION"),
        "non-op should be denied: {denied}"
    );
}

#[tokio::test]
async fn labeled_response_tags_the_reply() {
    let mut a = Conn::spawn(test_context(), 9501);
    a.send("CAP REQ :labeled-response").await;
    a.expect("ACK").await;
    a.send("NICK alice").await;
    a.send("USER alice 0 * :A").await;
    a.send("CAP END").await;
    a.expect("001").await;

    a.send("@label=abc WHOIS alice").await;
    let resp = a.expect("label=abc").await;
    assert!(resp.contains("label=abc"), "response not labeled: {resp}");
}

#[tokio::test]
async fn list_shows_public_channels() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9601);
    a.register("alice").await;
    a.send("JOIN #public").await;
    a.expect("End of /NAMES").await;
    a.send("LIST").await;
    let list = a.expect("323").await;
    assert!(
        list.contains("#public") && list.contains(" 322 "),
        "bad LIST: {list}"
    );
}

#[tokio::test]
async fn isupport_advertises_expanded_tokens() {
    let mut a = Conn::spawn(test_context(), 9750);
    a.register("alice").await;
    // ISUPPORT spans several 005 lines; NETWORK= is the last token, so reading up
    // to it captures every chunk.
    let isupport = a.expect("NETWORK=").await;
    for token in [
        "MODES=",
        "CHANLIMIT=#:",
        "UTF8ONLY",
        "CHATHISTORY=",
        "SAFELIST",
    ] {
        assert!(
            isupport.contains(token),
            "ISUPPORT missing {token}: {isupport}"
        );
    }
}

#[tokio::test]
async fn info_and_query_commands_respond() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9801);
    a.register("alice").await;

    a.send("VERSION").await;
    a.expect(" 351 ").await;
    a.send("TIME").await;
    a.expect(" 391 ").await;
    a.send("ADMIN").await;
    a.expect(" 259 ").await;
    a.send("INFO").await;
    a.expect(" 374 ").await;

    a.send("USERHOST alice").await;
    let uh = a.expect(" 302 ").await;
    assert!(uh.contains("alice=+"), "bad USERHOST: {uh}");

    a.send("ISON alice bob").await;
    let ison = a.expect(" 303 ").await;
    assert!(
        ison.contains("alice") && !ison.contains("bob"),
        "bad ISON: {ison}"
    );
}

#[tokio::test]
async fn channel_limit_is_enforced() {
    // A context with a tiny per-client channel cap.
    let server = Server::new(ServerInfo {
        name: "irc.test".to_owned(),
        sid: "42T".to_owned(),
        network: "TestNet".to_owned(),
        icon: None,
        version: "ferrixd-test".to_owned(),
        created: "c".to_owned(),
        casemapping: CaseMapping::Ascii,
        motd: Vec::new(),
        history_len: 500,
        history_max_targets: 50_000,
        max_channels: 2,
        cloak_key: None,
        sts: None,
    });
    let ctx = ConnContext {
        server,
        limits: Limits::default(),
        max_line: 8704,
        registration_timeout: Duration::from_secs(5),
        max_clients_per_ip: 100,
        sendq_lines: 1024,
        recv_burst: 200,
        recv_rate: 200,
        ping_interval: Duration::from_secs(120),
    };
    let mut a = Conn::spawn(ctx, 9820);
    a.register("alice").await;
    a.send("JOIN #a").await;
    a.expect("End of /NAMES").await;
    a.send("JOIN #b").await;
    a.expect("End of /NAMES").await;
    // The third join exceeds the cap → ERR_TOOMANYCHANNELS (405).
    a.send("JOIN #c").await;
    let err = a.expect(" 405 ").await;
    assert!(err.contains("#c"), "expected ERR_TOOMANYCHANNELS: {err}");
}

#[tokio::test]
async fn whox_returns_requested_fields() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9940);
    a.register("alice").await;
    a.send("JOIN #w").await;
    a.expect("End of /NAMES").await;

    // WHOX: querytype 42, fields t,c,u,h,n,f,a,r.
    a.send("WHO #w %tcuhnfar,42").await;
    let r = a.expect(" 354 ").await;
    assert!(r.contains(" 42 "), "querytype not echoed: {r}");
    assert!(
        r.contains("#w") && r.contains("alice"),
        "WHOX fields missing: {r}"
    );
    a.expect(" 315 ").await; // End of WHO

    // Legacy WHO (no %) still returns the classic 352.
    a.send("WHO #w").await;
    let legacy = a.expect(" 352 ").await;
    assert!(legacy.contains("alice"), "legacy WHO broken: {legacy}");
}

#[tokio::test]
async fn who_mask_respects_invisibility() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9944);
    a.register("alice").await;
    let mut b = Conn::spawn(ctx.clone(), 9945);
    b.register("bobby").await;

    // A mask WHO finds bobby by glob; `WHO 0` lists everyone visible.
    a.send("WHO bob*").await;
    let masked = a.expect(" 315 ").await;
    assert!(masked.contains("bobby"), "mask WHO missed bobby: {masked}");
    a.send("WHO 0").await;
    let all = a.expect(" 315 ").await;
    assert!(
        all.contains("alice") && all.contains("bobby"),
        "WHO 0 incomplete: {all}"
    );

    // Once bobby goes invisible (+i), a stranger no longer sees him…
    b.send("MODE bobby +i").await;
    b.expect("MODE").await;
    a.send("WHO bob*").await;
    let hidden = a.expect(" 315 ").await;
    assert!(
        !hidden.contains("bobby"),
        "invisible user leaked through mask WHO: {hidden}"
    );

    // …but sharing a channel makes him visible again.
    a.send("JOIN #shared").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #shared").await;
    b.expect("End of /NAMES").await;
    a.send("WHO bob*").await;
    let shared = a.expect(" 315 ").await;
    assert!(
        shared.contains("bobby"),
        "co-member hidden despite shared channel: {shared}"
    );
}

#[tokio::test]
async fn monitor_notifies_on_presence_change() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9920);
    a.register("alice").await;

    // Monitor bob while he is offline → RPL_MONOFFLINE (731).
    a.send("MONITOR + bob").await;
    let off = a.expect(" 731 ").await;
    assert!(off.contains("bob"), "expected MONOFFLINE: {off}");

    // Bob connects → alice gets RPL_MONONLINE (730) with his mask.
    let mut b = Conn::spawn(ctx.clone(), 9921);
    b.register("bob").await;
    let on = a.expect(" 730 ").await;
    assert!(on.contains("bob!"), "expected MONONLINE with mask: {on}");

    // MONITOR L lists him.
    a.send("MONITOR L").await;
    let l = a.expect(" 733 ").await; // RPL_ENDOFMONLIST, preceded by 732
    assert!(l.contains("bob"), "MONLIST missing bob: {l}");

    // Bob quits → alice gets RPL_MONOFFLINE again.
    b.send("QUIT :bye").await;
    let off2 = a.expect(" 731 ").await;
    assert!(off2.contains("bob"), "expected MONOFFLINE on quit: {off2}");
}

#[tokio::test]
async fn ban_exception_overrides_ban() {
    let ctx = test_context();
    let mut op = Conn::spawn(ctx.clone(), 9900);
    let mut u = Conn::spawn(ctx.clone(), 9901);
    op.register("op").await;
    u.register("user").await;

    op.send("JOIN #x").await;
    op.expect("End of /NAMES").await;
    op.send("MODE #x +b *!*@*").await; // ban everyone
    op.expect("MODE #x").await;

    // The banned user cannot join.
    u.send("JOIN #x").await;
    u.expect(" 474 ").await; // ERR_BANNEDFROMCHAN

    // Add a matching +e exception; the same user can now join.
    op.send("MODE #x +e *!*@127.0.0.1").await;
    op.expect("MODE #x").await;
    // The exception list is readable.
    op.send("MODE #x e").await;
    let elist = op.expect(" 349 ").await;
    assert!(
        elist.contains("*!*@127.0.0.1"),
        "exception not listed: {elist}"
    );

    u.send("JOIN #x").await;
    u.expect("End of /NAMES").await; // success despite the +b
}

#[tokio::test]
async fn user_modes_and_wallops() {
    let ctx = test_context_with_oper("admin", "secret");
    let mut op = Conn::spawn(ctx.clone(), 9880);
    let mut u = Conn::spawn(ctx.clone(), 9881);
    op.register("admin").await;
    u.register("user").await;

    // The user sets +i and +w, then queries their modes.
    u.send("MODE user +iw").await;
    let echo = u.expect("MODE user").await;
    assert!(echo.contains("+iw"), "unexpected umode echo: {echo}");
    u.send("MODE user").await;
    let umodeis = u.expect(" 221 ").await;
    assert!(
        umodeis.contains('i') && umodeis.contains('w'),
        "RPL_UMODEIS wrong: {umodeis}"
    );

    // An operator's WALLOPS reaches the +w user.
    op.send("OPER admin secret").await;
    op.expect("381").await;
    op.send("WALLOPS :maintenance in 5 minutes").await;
    let w = u.expect("WALLOPS").await;
    assert!(
        w.contains("maintenance in 5 minutes") && w.contains(":admin!"),
        "WALLOPS not delivered to +w user: {w}"
    );
}

#[tokio::test]
async fn tagmsg_relays_client_tags_only_to_message_tags_recipients() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9840);
    let mut b = Conn::spawn(ctx.clone(), 9841);
    let mut c = Conn::spawn(ctx.clone(), 9842);
    a.register_caps("alice", "message-tags").await;
    b.register_caps("bob", "message-tags").await;
    c.register("carol").await; // no message-tags

    a.send("JOIN #tag").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #tag").await;
    b.expect("End of /NAMES").await;
    c.send("JOIN #tag").await;
    c.expect("End of /NAMES").await;

    a.send("@+typing=active TAGMSG #tag").await;
    let got = b.expect("TAGMSG").await;
    assert!(
        got.contains("+typing=active"),
        "bob missing client tag: {got}"
    );
    assert!(got.contains(":alice!"), "TAGMSG missing source: {got}");

    // Carol has no message-tags: she must not receive the TAGMSG. Prove it by
    // sending a normal message next — her next line must be the PRIVMSG.
    a.send("PRIVMSG #tag :hello").await;
    let carol_line = c.expect("hello").await;
    assert!(
        !carol_line.contains("TAGMSG"),
        "carol without message-tags received a TAGMSG: {carol_line}"
    );
}

#[tokio::test]
async fn account_notify_announces_login_to_capable_members() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9860);
    let mut b = Conn::spawn(ctx.clone(), 9861);
    a.register("alice").await;
    b.register_caps("bob", "account-notify").await;

    a.send("JOIN #acc").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #acc").await;
    b.expect("End of /NAMES").await;
    a.expect("JOIN").await; // bob's join

    // Alice self-registers an account; bob (account-notify) is told.
    a.send("REGISTER * * s3cret").await;
    let acct = b.expect("ACCOUNT").await;
    assert!(
        acct.contains(":alice!") && acct.contains("ACCOUNT alice"),
        "bad ACCOUNT notification: {acct}"
    );
}

#[tokio::test]
async fn secret_channel_membership_hidden_from_nonmembers() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9701);
    let mut bob = Conn::spawn(ctx.clone(), 9702);
    alice.register("alice").await;
    bob.register("bob").await;

    alice.send("JOIN #hush").await;
    alice.expect("End of /NAMES").await;
    alice.send("MODE #hush +s").await;
    alice.expect("MODE #hush").await;

    // A non-member NAMES must reveal nothing but the terminator (no 353, no nick).
    bob.send("NAMES #hush").await;
    let names = bob.expect(" 366 ").await;
    assert!(
        !names.contains("alice") && !names.contains(" 353 "),
        "secret channel leaked membership via NAMES: {names}"
    );

    // A non-member WHO must reveal nothing but the terminator (no 352, no nick).
    bob.send("WHO #hush").await;
    let who = bob.expect(" 315 ").await;
    assert!(
        !who.contains("alice") && !who.contains(" 352 "),
        "secret channel leaked membership via WHO: {who}"
    );

    // A member still sees the listing.
    alice.send("NAMES #hush").await;
    let seen = alice.expect(" 366 ").await;
    assert!(
        seen.contains("alice"),
        "member cannot see their own secret channel: {seen}"
    );
}

#[tokio::test]
async fn direct_message_history_is_recorded() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9701);
    let mut b = Conn::spawn(ctx.clone(), 9702);
    a.register("alice").await;
    b.register("bob").await;
    a.send("PRIVMSG bob :hey bob").await;
    b.expect("hey bob").await;

    b.send("CAP REQ :batch draft/chathistory message-tags server-time")
        .await;
    b.expect("ACK").await;
    b.send("CHATHISTORY LATEST alice * 10").await;
    let hist = b.expect("BATCH -").await;
    assert!(hist.contains("hey bob"), "DM missing from history: {hist}");
}

#[tokio::test]
async fn multiline_batch_is_delivered() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9801);
    let mut b = Conn::spawn(ctx.clone(), 9802);
    a.register("alice").await;
    b.register("bob").await;
    a.send("JOIN #r").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #r").await;
    b.expect("End of /NAMES").await;
    a.expect("JOIN").await;

    a.send("CAP REQ :batch draft/multiline").await;
    a.expect("ACK").await;
    a.send("BATCH +ml draft/multiline #r").await;
    a.send("@batch=ml PRIVMSG #r :line one").await;
    a.send("@batch=ml PRIVMSG #r :line two").await;
    a.send("BATCH -ml").await;

    let got = b.expect("line two").await;
    assert!(
        got.contains("line one") && got.contains("line two"),
        "multiline not delivered: {got}"
    );
}

#[tokio::test]
async fn register_creates_and_logs_in_account() {
    let mut a = Conn::spawn(test_context(), 9901);
    a.register("alice").await;
    a.send("REGISTER * * s3cret").await;
    let reply = a.expect("REGISTER").await;
    assert!(
        reply.contains("SUCCESS") && reply.contains("alice"),
        "REGISTER failed: {reply}"
    );

    a.send("WHOIS alice").await;
    let whois = a.expect("End of /WHOIS").await;
    assert!(
        whois.contains("330"),
        "account not set after REGISTER: {whois}"
    );
}

#[tokio::test]
async fn whowas_remembers_departed_nicks() {
    let ctx = test_context();
    let mut ghost = Conn::spawn(ctx.clone(), 9911);
    ghost.register("casper").await;
    ghost.send("QUIT :gone").await;
    ghost.expect("ERROR").await;

    let mut a = Conn::spawn(ctx.clone(), 9912);
    a.register("alice").await;
    a.send("WHOWAS casper").await;
    let reply = a.expect("End of WHOWAS").await;
    assert!(reply.contains("314"), "no RPL_WHOWASUSER: {reply}");
    assert!(reply.contains("casper"), "wrong nick in WHOWAS: {reply}");

    a.send("WHOWAS nobody").await;
    let reply = a.expect("End of WHOWAS").await;
    assert!(reply.contains("406"), "no ERR_WASNOSUCHNICK: {reply}");
}

#[tokio::test]
async fn nick_change_records_whowas() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9913);
    a.register("early").await;
    a.send("NICK late").await;
    a.expect("NICK").await;
    a.send("WHOWAS early").await;
    let reply = a.expect("End of WHOWAS").await;
    assert!(reply.contains("314"), "old nick not in WHOWAS: {reply}");
}

#[tokio::test]
async fn help_lists_topics_and_details() {
    let mut a = Conn::spawn(test_context(), 9921);
    a.register("alice").await;
    a.send("HELP").await;
    let index = a.expect("End of /HELP").await;
    assert!(index.contains("704"), "no RPL_HELPSTART: {index}");
    assert!(index.contains("JOIN"), "JOIN missing from index: {index}");

    a.send("HELP JOIN").await;
    let topic = a.expect("End of /HELP").await;
    assert!(topic.contains("JOIN <#chan>"), "no JOIN usage: {topic}");

    a.send("HELP NOPE").await;
    let miss = a.expect("524").await;
    assert!(miss.contains("NOPE"), "524 lacks subject: {miss}");
}

#[tokio::test]
async fn links_lists_this_server() {
    let mut a = Conn::spawn(test_context(), 9931);
    a.register("alice").await;
    a.send("LINKS").await;
    let reply = a.expect("End of /LINKS").await;
    assert!(reply.contains("364"), "no RPL_LINKS row: {reply}");
    assert!(
        reply.contains("irc.test"),
        "self missing from LINKS: {reply}"
    );
}

#[tokio::test]
async fn stats_uptime_public_bans_gated() {
    let ctx = test_context_with_oper("admin", "secret");
    let mut a = Conn::spawn(ctx.clone(), 9941);
    a.register("alice").await;

    a.send("STATS u").await;
    let uptime = a.expect("End of /STATS").await;
    assert!(uptime.contains("242"), "no RPL_STATSUPTIME: {uptime}");

    // K-Line listing requires oper.
    a.send("STATS k").await;
    let denied = a.expect("481").await;
    assert!(denied.contains("481"), "STATS k not gated: {denied}");

    a.send("OPER admin secret").await;
    a.expect("381").await;
    a.send("KLINE spam!*@* :flood").await;
    a.expect("Added K-Line").await;
    a.send("STATS k").await;
    let klines = a.expect("End of /STATS").await;
    assert!(
        klines.contains("216") && klines.contains("spam!*@*"),
        "K-Line missing from STATS k: {klines}"
    );
}

#[tokio::test]
async fn knock_notifies_channel_ops() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9951);
    let mut b = Conn::spawn(ctx.clone(), 9952);
    a.register("alice").await;
    b.register("bob").await;

    a.send("JOIN #priv").await;
    a.expect("End of /NAMES").await;

    // Knocking on an open channel is refused.
    b.send("KNOCK #priv").await;
    let open = b.expect("713").await;
    assert!(open.contains("Channel is open"), "no ERR_CHANOPEN: {open}");

    a.send("MODE #priv +i").await;
    a.expect("+i").await;

    b.send("KNOCK #priv").await;
    let delivered = b.expect("711").await;
    assert!(
        delivered.contains("KNOCK has been delivered"),
        "no RPL_KNOCKDLVR: {delivered}"
    );
    let knock = a.expect("710").await;
    assert!(
        knock.contains("bob") && knock.contains("asked for an invite"),
        "op did not see the knock: {knock}"
    );
}

#[tokio::test]
async fn invite_with_no_args_lists_pending_invites() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9961);
    let mut b = Conn::spawn(ctx.clone(), 9962);
    a.register("alice").await;
    b.register("bob").await;

    a.send("JOIN #inner").await;
    a.expect("End of /NAMES").await;
    a.send("MODE #inner +i").await;
    a.expect("+i").await;
    a.send("INVITE bob #inner").await;
    b.expect("INVITE").await;

    b.send("INVITE").await;
    let list = b.expect("End of /INVITE list").await;
    assert!(list.contains("#inner"), "pending invite missing: {list}");
}

#[tokio::test]
async fn pass_gates_registration_when_configured() {
    let ctx = test_context();
    ctx.server.set_client_password(Some("letmein".to_owned()));

    // No PASS: refused with 464 and disconnected.
    let mut bad = Conn::spawn(ctx.clone(), 9971);
    bad.send("NICK eve").await;
    bad.send("USER eve 0 * :Eve").await;
    let refused = bad.expect("ERROR").await;
    assert!(refused.contains("464"), "no ERR_PASSWDMISMATCH: {refused}");

    // Correct PASS: registration completes.
    let mut good = Conn::spawn(ctx.clone(), 9972);
    good.send("PASS letmein").await;
    good.register("alice").await;
}

#[tokio::test]
async fn whois_shows_operator_and_kill_guards_servers() {
    let ctx = test_context_with_oper("admin", "secret");
    let mut a = Conn::spawn(ctx.clone(), 9981);
    a.register("alice").await;
    a.send("OPER admin secret").await;
    a.expect("381").await;

    a.send("WHOIS alice").await;
    let whois = a.expect("End of /WHOIS").await;
    assert!(whois.contains("313"), "no RPL_WHOISOPERATOR: {whois}");

    a.send("KILL irc.test :nope").await;
    let guarded = a.expect("483").await;
    assert!(
        guarded.contains("can't kill a server"),
        "no ERR_CANTKILLSERVER: {guarded}"
    );
}

#[tokio::test]
async fn list_supports_elist_filters() {
    let ctx = test_context();
    let mut a = Conn::spawn(ctx.clone(), 9991);
    let mut b = Conn::spawn(ctx.clone(), 9992);
    a.register("alice").await;
    b.register("bob").await;

    a.send("JOIN #big").await;
    a.expect("End of /NAMES").await;
    b.send("JOIN #big").await;
    b.expect("End of /NAMES").await;
    a.send("JOIN #small").await;
    a.expect("End of /NAMES").await;

    // More than one member: only #big qualifies.
    a.send("LIST >1").await;
    let big = a.expect("End of /LIST").await;
    assert!(big.contains("#big"), "#big missing from LIST >1: {big}");
    assert!(!big.contains("#small"), "#small wrongly in LIST >1: {big}");

    // Name mask.
    a.send("LIST *mall").await;
    let small = a.expect("End of /LIST").await;
    assert!(
        small.contains("#small"),
        "#small missing from mask: {small}"
    );
    assert!(
        !small.contains("#big"),
        "#big wrongly in mask list: {small}"
    );

    // Negated mask.
    a.send("LIST !*mall").await;
    let notsmall = a.expect("End of /LIST").await;
    assert!(
        notsmall.contains("#big"),
        "#big missing from !mask: {notsmall}"
    );
    assert!(
        !notsmall.contains("#small"),
        "#small wrongly in !mask list: {notsmall}"
    );
}

#[tokio::test]
async fn statusmsg_reaches_only_prefixed_members() {
    let ctx = test_context();
    let mut op = Conn::spawn(ctx.clone(), 9901);
    let mut plain = Conn::spawn(ctx.clone(), 9902);
    let mut sender = Conn::spawn(ctx.clone(), 9903);
    op.register("opal").await;
    plain.register("pat").await;
    sender.register("sam").await;

    // opal creates the channel (and is op); pat and sam join unprefixed.
    op.send("JOIN #status").await;
    op.expect("End of /NAMES").await;
    plain.send("JOIN #status").await;
    plain.expect("End of /NAMES").await;
    sender.send("JOIN #status").await;
    sender.expect("End of /NAMES").await;
    op.expect("sam").await; // both joins observed

    sender.send("PRIVMSG @#status :ops only").await;
    let got = op.expect("ops only").await;
    assert!(
        got.contains("@#status"),
        "STATUSMSG target rewritten: {got}"
    );

    // The unprefixed member must not see it; the next line it reads is the
    // regular channel message sent afterwards.
    sender.send("PRIVMSG #status :for everyone").await;
    let next = plain.expect("PRIVMSG").await;
    assert!(
        next.contains("for everyone") && !next.contains("ops only"),
        "statusmsg leaked to unprefixed member: {next}"
    );
}

// ------------------------------------------------------------- new caps ---

#[tokio::test]
async fn sts_is_advertised_per_connection_security() {
    let mut ctx = test_context();
    let info = Arc::get_mut(&mut ctx.server).expect("fresh server");
    info.info.sts = Some(ferrixd::config::StsConfig {
        port: 6697,
        duration: 300,
        preload: true,
    });

    // A plaintext connection is told the TLS port to upgrade to.
    let mut plain = Conn::spawn(ctx.clone(), 9911);
    plain.send("CAP LS 302").await;
    let ls = plain.expect("CAP").await;
    assert!(ls.contains("sts=port=6697"), "no sts upgrade token: {ls}");

    // A TLS connection is told to persist the policy.
    let mut secure = Conn::spawn_with(ctx.clone(), 9912, true);
    secure.send("CAP LS 302").await;
    let ls = secure.expect("CAP").await;
    assert!(
        ls.contains("sts=duration=300,preload"),
        "no sts duration token: {ls}"
    );
    // sts must not be REQable.
    secure.send("CAP REQ :sts").await;
    secure.expect("NAK").await;
}

#[tokio::test]
async fn extended_monitor_forwards_away_and_account_events() {
    let ctx = test_context();
    let mut watcher = Conn::spawn(ctx.clone(), 9921);
    let mut target = Conn::spawn(ctx.clone(), 9922);
    watcher
        .register_caps("watcher", "extended-monitor away-notify setname")
        .await;
    target.register("tara").await;

    watcher.send("MONITOR + tara").await;
    watcher.expect("730").await; // RPL_MONONLINE — tara is online

    // No shared channel — only extended-monitor can deliver these.
    target.send("AWAY :fishing").await;
    let away = watcher.expect("AWAY").await;
    assert!(
        away.contains(":tara!~tara@127.0.0.1 AWAY :fishing"),
        "watcher did not get AWAY: {away}"
    );

    target.send("SETNAME :Tara Renamed").await;
    let setname = watcher.expect("SETNAME").await;
    assert!(
        setname.contains("SETNAME :Tara Renamed"),
        "watcher did not get SETNAME: {setname}"
    );
}

#[tokio::test]
async fn read_marker_is_monotonic_and_replies() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9931);
    alice.register_caps("alice", "draft/read-marker").await;

    // Unset marker reads back as `*`.
    alice.send("MARKREAD #room").await;
    let unset = alice.expect("MARKREAD").await;
    assert!(unset.contains("MARKREAD #room *"), "expected *: {unset}");

    // Set, read back, and refuse to move backwards.
    alice
        .send("MARKREAD #room timestamp=2026-07-14T10:00:00.000Z")
        .await;
    alice.expect("timestamp=2026-07-14T10:00:00.000Z").await;
    alice
        .send("MARKREAD #room timestamp=2026-07-14T09:00:00.000Z")
        .await;
    let still = alice.expect("MARKREAD").await;
    assert!(
        still.contains("timestamp=2026-07-14T10:00:00.000Z"),
        "marker moved backwards: {still}"
    );

    // Garbage timestamps FAIL.
    alice.send("MARKREAD #room timestamp=yesterday").await;
    alice.expect("INVALID_PARAMS").await;
}

#[tokio::test]
async fn event_playback_gates_join_part_replay() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9941);
    let mut bob = Conn::spawn(ctx.clone(), 9942);
    alice.register("alice").await;
    bob.register("bob").await;
    alice.send("JOIN #hist").await;
    alice.expect("End of /NAMES").await;
    bob.send("JOIN #hist").await;
    bob.expect("End of /NAMES").await;
    alice.expect("JOIN").await;
    alice.send("PRIVMSG #hist :the message").await;
    bob.expect("the message").await;
    bob.send("PART #hist :done here").await;
    alice.expect("PART").await;

    // A capable client sees JOIN/PART events in replay…
    let mut eve = Conn::spawn(ctx.clone(), 9943);
    eve.register_caps("eve", "batch draft/chathistory draft/event-playback")
        .await;
    eve.send("JOIN #hist").await;
    eve.expect("End of /NAMES").await;
    eve.send("CHATHISTORY LATEST #hist * 50").await;
    let replay = eve.expect("BATCH -").await;
    assert!(replay.contains("the message"), "message missing: {replay}");
    assert!(
        replay.contains("JOIN #hist"),
        "join event not replayed: {replay}"
    );
    assert!(
        replay.contains("PART #hist :done here"),
        "part event not replayed: {replay}"
    );

    // …a plain client only gets messages.
    let mut carl = Conn::spawn(ctx.clone(), 9944);
    carl.register_caps("carl", "batch draft/chathistory").await;
    carl.send("JOIN #hist").await;
    carl.expect("End of /NAMES").await;
    carl.send("CHATHISTORY LATEST #hist * 50").await;
    let replay = carl.expect("BATCH -").await;
    assert!(replay.contains("the message"), "message missing: {replay}");
    assert!(
        !replay.contains("PART #hist"),
        "events leaked without the cap: {replay}"
    );
}

#[tokio::test]
async fn redact_deletes_from_history_and_notifies() {
    let ctx = test_context();
    let mut op = Conn::spawn(ctx.clone(), 9951);
    let mut bob = Conn::spawn(ctx.clone(), 9952);
    op.register_caps("opal", "message-tags draft/message-redaction")
        .await;
    bob.register_caps(
        "bob",
        "message-tags draft/message-redaction batch draft/chathistory",
    )
    .await;
    op.send("JOIN #mod").await;
    op.expect("End of /NAMES").await;
    bob.send("JOIN #mod").await;
    bob.expect("End of /NAMES").await;
    op.expect("JOIN").await;

    // Bob speaks; the op reads the msgid off the delivered tags.
    bob.send("PRIVMSG #mod :accidental secret").await;
    let seen = op.expect("accidental secret").await;
    let line = seen
        .lines()
        .find(|l| l.contains("accidental secret"))
        .unwrap();
    let msgid = line
        .split(';')
        .flat_map(|part| part.split('@'))
        .find_map(|part| part.strip_prefix("msgid="))
        .map(|rest| rest.split_whitespace().next().unwrap())
        .expect("delivered message carries a msgid");

    // A non-author non-op cannot redact — but the channel op can.
    op.send(&format!("REDACT #mod {msgid} :cleanup")).await;
    let redact = bob.expect("REDACT").await;
    assert!(
        redact.contains(&format!("REDACT #mod {msgid} :cleanup")),
        "bob did not see the redaction: {redact}"
    );

    // The message is gone from replay.
    bob.send("CHATHISTORY LATEST #mod * 50").await;
    let replay = bob.expect("BATCH -").await;
    assert!(
        !replay.contains("accidental secret"),
        "redacted message still replayed: {replay}"
    );

    // Redacting an unknown msgid FAILs.
    op.send("REDACT #mod 42T-ffffffffffffffff").await;
    op.expect("UNKNOWN_MSGID").await;
}

#[tokio::test]
async fn rename_moves_channel_and_resyncs_noncap_members() {
    let ctx = test_context();
    let mut op = Conn::spawn(ctx.clone(), 9961);
    let mut bob = Conn::spawn(ctx.clone(), 9962);
    op.register_caps("opal", "draft/channel-rename").await;
    bob.register("bob").await;
    op.send("JOIN #before").await;
    op.expect("End of /NAMES").await;
    bob.send("JOIN #before").await;
    bob.expect("End of /NAMES").await;
    op.expect("JOIN").await;

    op.send("RENAME #before #after :fresh start").await;
    let seen = op.expect("RENAME").await;
    assert!(
        seen.contains("RENAME #before #after :fresh start"),
        "op did not see RENAME: {seen}"
    );
    // The cap-less member is resynced via PART/JOIN + NAMES.
    let resync = bob.expect("End of /NAMES").await;
    assert!(
        resync.contains("PART #before") && resync.contains("JOIN #after"),
        "bob was not resynced: {resync}"
    );

    // The channel now answers to the new name only, membership intact.
    op.send("PRIVMSG #after :works").await;
    let got = bob.expect("works").await;
    assert!(got.contains("PRIVMSG #after"), "bad delivery: {got}");
    op.send("PRIVMSG #before :dead").await;
    op.expect("401").await;

    // A rename onto an existing channel is refused.
    bob.send("JOIN #taken").await;
    bob.expect("End of /NAMES").await;
    op.send("RENAME #after #taken").await;
    op.expect("CHANNEL_NAME_IN_USE").await;
}

// ------------------------------------------------- audit-backlog fixes ---

#[tokio::test]
async fn labeled_response_labels_the_echo_instead_of_acking() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9971);
    alice
        .register_caps(
            "alice",
            "labeled-response echo-message message-tags batch server-time",
        )
        .await;
    alice.send("JOIN #lab").await;
    alice.expect("End of /NAMES").await;

    // The echo itself must carry the label — and there must be no bare ACK.
    alice
        .send("@label=abc PRIVMSG #lab :hello with a label")
        .await;
    let echoed = alice.expect("hello with a label").await;
    assert!(
        echoed.contains("label=abc"),
        "echo was not labeled: {echoed}"
    );
    assert!(
        !echoed.contains(" ACK"),
        "a labeled echo must not also produce an ACK: {echoed}"
    );
}

#[tokio::test]
async fn advertised_limits_are_enforced() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9972);
    alice.register("alice").await;
    alice.send("JOIN #lim").await;
    alice.expect("End of /NAMES").await;

    // TOPICLEN=390: a longer topic is truncated, not stored whole.
    let long_topic = "t".repeat(500);
    alice.send(&format!("TOPIC #lim :{long_topic}")).await;
    let topic = alice.expect("TOPIC #lim").await;
    let set = topic
        .lines()
        .find(|l| l.contains("TOPIC #lim"))
        .and_then(|l| l.split(':').nth(2))
        .unwrap_or_default();
    assert_eq!(set.len(), 390, "topic was not truncated to TOPICLEN");

    // MODES=6: only the first six changes of one MODE command apply.
    alice
        .send("MODE #lim +bbbbbbbb a1!*@* a2!*@* a3!*@* a4!*@* a5!*@* a6!*@* a7!*@* a8!*@*")
        .await;
    alice.expect("MODE #lim").await;
    alice.send("MODE #lim b").await;
    let bans = alice.expect("End of channel ban list").await;
    let count = bans.lines().filter(|l| l.contains(" 367 ")).count();
    assert_eq!(count, 6, "MODES=6 was not enforced: {bans}");
}

#[tokio::test]
async fn join_zero_parts_every_channel() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9973);
    let mut bob = Conn::spawn(ctx.clone(), 9974);
    alice.register("alice").await;
    bob.register("bob").await;
    for chan in ["#one", "#two"] {
        alice.send(&format!("JOIN {chan}")).await;
        alice.expect("End of /NAMES").await;
        bob.send(&format!("JOIN {chan}")).await;
        bob.expect("End of /NAMES").await;
        alice.expect("JOIN").await;
    }

    alice.send("JOIN 0").await;
    // JOIN 0 parts every channel, but the order of the PART messages follows
    // the server's (non-deterministic) channel iteration order. Read PART lines
    // until both channels have been seen instead of assuming #two arrives last.
    let mut seen = String::new();
    while !(seen.contains("PART #one") && seen.contains("PART #two")) {
        seen.push_str(&bob.expect("PART #").await);
    }
}

#[tokio::test]
async fn kick_accepts_comma_lists() {
    let ctx = test_context();
    let mut op = Conn::spawn(ctx.clone(), 9975);
    let mut bob = Conn::spawn(ctx.clone(), 9976);
    let mut carl = Conn::spawn(ctx.clone(), 9977);
    op.register("opal").await;
    bob.register("bob").await;
    carl.register("carl").await;
    op.send("JOIN #k").await;
    op.expect("End of /NAMES").await;
    for c in [&mut bob, &mut carl] {
        c.send("JOIN #k").await;
        c.expect("End of /NAMES").await;
    }
    op.expect("carl").await;

    op.send("KICK #k bob,carl :out").await;
    let kicks = op.expect("KICK #k carl").await;
    assert!(
        kicks.contains("KICK #k bob") && kicks.contains("KICK #k carl"),
        "comma-list KICK did not kick both: {kicks}"
    );
}

#[tokio::test]
async fn multiline_enforces_limits_and_delivers_a_batch() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9978);
    let mut bob = Conn::spawn(ctx.clone(), 9979);
    alice
        .register_caps("alice", "draft/multiline batch message-tags")
        .await;
    bob.register_caps("bob", "draft/multiline batch message-tags")
        .await;
    alice.send("JOIN #ml").await;
    alice.expect("End of /NAMES").await;
    bob.send("JOIN #ml").await;
    bob.expect("End of /NAMES").await;
    alice.expect("JOIN").await;

    // A capable recipient gets a real batch around the lines.
    alice.send("BATCH +ml draft/multiline #ml").await;
    alice.send("@batch=ml PRIVMSG #ml :line one").await;
    alice.send("@batch=ml PRIVMSG #ml :line two").await;
    alice.send("BATCH -ml").await;
    let seen = bob.expect("BATCH -").await;
    assert!(
        seen.contains("BATCH +") && seen.contains("draft/multiline #ml"),
        "no multiline batch was opened: {seen}"
    );
    assert!(
        seen.contains("line one") && seen.contains("line two"),
        "batch lines missing: {seen}"
    );

    // Exceeding max-lines fails the batch instead of silently truncating.
    alice.send("BATCH +big draft/multiline #ml").await;
    for i in 0..101 {
        alice
            .send(&format!("@batch=big PRIVMSG #ml :flood {i}"))
            .await;
    }
    alice.expect("MULTILINE_MAX_LINES").await;
}

#[tokio::test]
async fn metadata_subscribers_are_notified() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9980);
    let mut bob = Conn::spawn(ctx.clone(), 9981);
    alice.register_caps("alice", "draft/metadata-2").await;
    bob.register_caps("bob", "draft/metadata-2").await;
    alice.send("JOIN #meta").await;
    alice.expect("End of /NAMES").await;
    bob.send("JOIN #meta").await;
    bob.expect("End of /NAMES").await;
    alice.expect("JOIN").await;

    bob.send("METADATA * SUB avatar").await;
    bob.expect("770").await; // RPL_METADATASUBOK

    alice.send("METADATA * SET avatar :https://ex/a.png").await;
    let event = bob.expect("METADATA").await;
    assert!(
        event.contains("METADATA alice avatar") && event.contains("https://ex/a.png"),
        "subscriber was not notified: {event}"
    );

    bob.send("METADATA * SUBS").await;
    let subs = bob.expect("End of metadata subscriptions").await;
    assert!(subs.contains("avatar"), "SUBS did not list the key: {subs}");
}

#[tokio::test]
async fn silence_drops_private_messages_from_matching_masks() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9982);
    let mut mallory = Conn::spawn(ctx.clone(), 9983);
    let mut bob = Conn::spawn(ctx.clone(), 9984);
    alice.register("alice").await;
    mallory.register("mallory").await;
    bob.register("bob").await;

    alice.send("SILENCE +mallory!*@*").await;
    alice.expect("271").await; // RPL_SILELIST

    mallory.send("PRIVMSG alice :you cannot ignore me").await;
    bob.send("PRIVMSG alice :but I get through").await;
    // The next message alice sees is bob's — mallory's was dropped entirely.
    let seen = alice.expect("PRIVMSG").await;
    assert!(
        seen.contains("but I get through") && !seen.contains("cannot ignore me"),
        "SILENCE did not drop the message: {seen}"
    );
}

#[tokio::test]
async fn chathistory_targets_lists_dm_partners() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx.clone(), 9985);
    let mut bob = Conn::spawn(ctx.clone(), 9986);
    alice
        .register_caps("alice", "batch draft/chathistory server-time")
        .await;
    bob.register("bob").await;

    bob.send("PRIVMSG alice :a direct message").await;
    alice.expect("a direct message").await;

    alice.send("CHATHISTORY TARGETS * * 50").await;
    let targets = alice.expect("CHATHISTORY TARGETS").await;
    assert!(
        targets.contains("TARGETS bob"),
        "the DM partner was not listed: {targets}"
    );
}

// ------------------------------------------------------------------------
// IRCv3 additions: bot-mode, no-implicit-names, pre-away, extended-isupport,
// network-icon, WEBIRC, and the WebSocket transport.
// ------------------------------------------------------------------------

/// A test context whose network advertises an icon URL (draft/network-icon).
fn test_context_with_icon(icon: &str) -> ConnContext {
    let mut ctx = test_context();
    let server = Server::new(ServerInfo {
        name: "irc.test".to_owned(),
        sid: "42T".to_owned(),
        network: "TestNet".to_owned(),
        icon: Some(icon.to_owned()),
        version: "ferrixd-test".to_owned(),
        created: "2026-07-08 00:00:00 UTC".to_owned(),
        casemapping: CaseMapping::Ascii,
        motd: Vec::new(),
        history_len: 500,
        history_max_targets: 50_000,
        max_channels: 50,
        cloak_key: None,
        sts: None,
    });
    ctx.server = server;
    ctx
}

#[tokio::test]
async fn bot_mode_shows_in_whois_who_and_message_tag() {
    let ctx = test_context();
    let mut bot = Conn::spawn(ctx.clone(), 9600);
    let mut watcher = Conn::spawn(ctx.clone(), 9601);
    bot.register("botty").await;
    watcher.register_caps("watcher", "message-tags").await;

    // Declare the bot; the change is echoed back.
    bot.send("MODE botty +B").await;
    bot.expect("MODE botty").await;

    // WHOIS carries RPL_WHOISBOT (335).
    watcher.send("WHOIS botty").await;
    let whois = watcher.expect("End of /WHOIS").await;
    assert!(whois.contains(" 335 "), "no RPL_WHOISBOT: {whois}");

    // The bot creates a channel (becomes op); WHO shows the bot flag `B`.
    bot.send("JOIN #c").await;
    bot.expect("End of /NAMES").await;
    watcher.send("JOIN #c").await;
    watcher.expect("End of /NAMES").await;
    watcher.send("WHO #c").await;
    let who = watcher.expect(" 315 ").await;
    let botline = who
        .lines()
        .find(|l| l.contains(" 352 ") && l.contains("botty"))
        .unwrap_or_else(|| panic!("no WHO row for botty: {who}"));
    assert!(botline.contains("HB"), "no bot flag in WHO row: {botline}");

    // A message from the bot carries a bare `@bot` tag for message-tags clients.
    bot.send("PRIVMSG #c :beep").await;
    let msg = watcher.expect("beep").await;
    let line = msg
        .lines()
        .rev()
        .find(|l| l.contains("PRIVMSG"))
        .unwrap_or_else(|| panic!("no PRIVMSG line: {msg}"));
    let tag_section = line
        .strip_prefix('@')
        .unwrap_or_else(|| panic!("PRIVMSG not tagged: {line}"))
        .split(' ')
        .next()
        .unwrap();
    assert!(
        tag_section.split(';').any(|t| t == "bot"),
        "no @bot tag: {line}"
    );
}

#[tokio::test]
async fn no_implicit_names_suppresses_join_names_burst() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx, 9610);
    alice.register_caps("alice", "no-implicit-names").await;

    // A PING/PONG barrier flushes everything the JOIN produced.
    alice.send("JOIN #x").await;
    alice.send("PING :sync").await;
    let after_join = alice.expect("PONG").await;
    assert!(after_join.contains("JOIN"), "no JOIN echo: {after_join}");
    assert!(
        !after_join.contains(" 353 ") && !after_join.contains(" 366 "),
        "implicit NAMES was not suppressed: {after_join}"
    );

    // An explicit NAMES still works.
    alice.send("NAMES #x").await;
    let names = alice.expect(" 366 ").await;
    assert!(
        names.contains(" 353 ") && names.contains("alice"),
        "explicit NAMES missing the member list: {names}"
    );
}

#[tokio::test]
async fn pre_away_is_accepted_before_registration() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx, 9620);
    alice.send("CAP REQ :draft/pre-away").await;
    alice.expect("ACK").await;

    // AWAY before registration is accepted (RPL_NOWAWAY, target `*`).
    alice.send("AWAY :back soon").await;
    alice.expect(" 306 ").await;

    alice.send("NICK alice").await;
    alice.send("USER alice 0 * :Alice").await;
    alice.send("CAP END").await;
    alice.expect(" 001 ").await;

    // The away status survived into the registered session.
    alice.send("WHOIS alice").await;
    let whois = alice.expect("End of /WHOIS").await;
    assert!(
        whois.contains("back soon"),
        "pre-registration AWAY was lost: {whois}"
    );
}

#[tokio::test]
async fn extended_isupport_arrives_before_welcome() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx, 9630);
    alice.send("CAP REQ :draft/extended-isupport").await;
    alice.expect("ACK").await;
    alice.send("NICK alice").await;
    alice.send("USER alice 0 * :Alice").await;
    alice.send("CAP END").await;

    // `expect` stops at the first line containing " 001 ". With the cap, ISUPPORT
    // is delivered during negotiation — i.e. BEFORE RPL_WELCOME — so it appears
    // in the accumulated text; without it, 005 would only follow 001.
    let before_welcome = alice.expect(" 001 ").await;
    assert!(
        before_welcome.contains(" 005 ") && before_welcome.contains("CASEMAPPING"),
        "ISUPPORT was not sent before RPL_WELCOME: {before_welcome}"
    );
}

#[tokio::test]
async fn network_icon_advertised_in_isupport() {
    let ctx = test_context_with_icon("https://example.org/icon.svg");
    let mut alice = Conn::spawn(ctx, 9640);
    alice.register("alice").await;
    let isupport = alice.expect("draft/ICON").await;
    assert!(
        isupport.contains("draft/ICON=https://example.org/icon.svg"),
        "network icon not advertised: {isupport}"
    );
}

#[tokio::test]
async fn bot_isupport_token_present() {
    let ctx = test_context();
    let mut alice = Conn::spawn(ctx, 9645);
    alice.register("alice").await;
    let isupport = alice.expect("CASEMAPPING").await;
    assert!(
        isupport.contains("BOT=B"),
        "no BOT ISUPPORT token: {isupport}"
    );
}

#[tokio::test]
async fn webirc_rewrites_apparent_host() {
    let ctx = test_context();
    ctx.server
        .set_webirc_gateways(vec![ferrixd::config::WebircConfig {
            name: "gw".to_owned(),
            password: "s3cret".to_owned(),
            hosts: vec!["127.0.0.1".to_owned()],
        }]);
    let mut bob = Conn::spawn(ctx, 9650);

    // WEBIRC must be the first command; it rewrites host and IP.
    bob.send("WEBIRC s3cret gw client.example.test 198.51.100.7")
        .await;
    let welcome = bob.register("bob").await;
    assert!(
        welcome.contains("bob!~bob@client.example.test"),
        "WEBIRC host was not applied: {welcome}"
    );

    // The real (spoofed) IP is visible to the user themself via RPL_WHOISACTUALLY.
    bob.send("WHOIS bob").await;
    let whois = bob.expect("End of /WHOIS").await;
    assert!(
        whois.contains("198.51.100.7"),
        "WEBIRC IP was not applied: {whois}"
    );
}

#[tokio::test]
async fn webirc_rejects_wrong_password() {
    let ctx = test_context();
    ctx.server
        .set_webirc_gateways(vec![ferrixd::config::WebircConfig {
            name: "gw".to_owned(),
            password: "s3cret".to_owned(),
            hosts: vec!["127.0.0.1".to_owned()],
        }]);
    let mut bob = Conn::spawn(ctx, 9655);
    bob.send("WEBIRC wrong gw client.example.test 198.51.100.7")
        .await;
    // A bad gateway secret closes the connection with an ERROR.
    let err = bob.expect("ERROR").await;
    assert!(
        err.contains("WEBIRC authentication failed"),
        "expected auth failure ERROR: {err}"
    );
}

/// A minimal RFC 6455 client used to drive the server's WebSocket transport
/// without pulling in a WebSocket crate. Each IRC line is one masked text frame;
/// server frames arrive unmasked.
struct WsTestClient<S> {
    io: S,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> WsTestClient<S> {
    /// Perform the client handshake and assert the server's `Sec-WebSocket-Accept`.
    async fn connect(mut io: S, subprotocol: &str) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // "dGhlIHNhbXBsZSBub25jZQ==" → RFC 6455's worked-example accept value.
        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {subprotocol}\r\n\r\n"
        );
        io.write_all(request.as_bytes()).await.unwrap();

        let mut resp = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                io.read(&mut byte),
            )
            .await
            .expect("WebSocket handshake timed out")
            .unwrap();
            assert!(n == 1, "EOF during handshake response");
            resp.push(byte[0]);
            if resp.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.contains("101 Switching Protocols"), "no 101: {resp}");
        assert!(
            resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "wrong Sec-WebSocket-Accept: {resp}"
        );
        assert!(
            resp.contains(&format!("Sec-WebSocket-Protocol: {subprotocol}")),
            "subprotocol not echoed: {resp}"
        );
        Self { io }
    }

    /// Send one IRC line as a masked WebSocket text frame.
    async fn send_line(&mut self, line: &str) {
        use tokio::io::AsyncWriteExt;
        let payload = line.as_bytes();
        assert!(payload.len() < 126, "test lines stay in the 7-bit length");
        let mask = [0x21u8, 0x43, 0x65, 0x87];
        let mut frame = vec![0x81u8, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.io.write_all(&frame).await.unwrap();
    }

    /// Read one server frame, returning `(opcode, payload)`.
    async fn recv_frame(&mut self) -> (u8, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 2];
        self.io.read_exact(&mut header).await.unwrap();
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let len7 = (header[1] & 0x7f) as usize;
        let len = if len7 < 126 {
            len7
        } else if len7 == 126 {
            let mut l = [0u8; 2];
            self.io.read_exact(&mut l).await.unwrap();
            u16::from_be_bytes(l) as usize
        } else {
            let mut l = [0u8; 8];
            self.io.read_exact(&mut l).await.unwrap();
            u64::from_be_bytes(l) as usize
        };
        let mask = if masked {
            let mut m = [0u8; 4];
            self.io.read_exact(&mut m).await.unwrap();
            Some(m)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        self.io.read_exact(&mut payload).await.unwrap();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        (opcode, payload)
    }
}

#[tokio::test]
async fn websocket_transport_registers_and_delivers() {
    let ctx = test_context();
    let max_line = ctx.max_line;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let peer = "127.0.0.1:9660".parse().unwrap();
    tokio::spawn(async move {
        let ws = ferrixd::websocket::accept(server_io, max_line)
            .await
            .expect("ws handshake");
        ferrixd::connection::serve(ws, peer, ctx, None, false).await;
    });

    let mut client = WsTestClient::connect(client_io, "text.ircv3.net").await;

    // Each IRC line is one WebSocket message, with no trailing CRLF.
    client.send_line("NICK alice").await;
    client.send_line("USER alice 0 * :Alice").await;

    // Read framed messages until RPL_WELCOME comes back over the socket.
    let mut saw_welcome = false;
    for _ in 0..50 {
        let (opcode, payload) = tokio::time::timeout(Duration::from_secs(3), client.recv_frame())
            .await
            .expect("ws read timeout");
        if opcode == 0x1 || opcode == 0x2 {
            let text = String::from_utf8_lossy(&payload);
            assert!(
                !text.ends_with('\n') && !text.ends_with('\r'),
                "WebSocket frame must not carry CRLF: {text:?}"
            );
            if text.contains(" 001 ") {
                saw_welcome = true;
                break;
            }
        }
    }
    assert!(saw_welcome, "no RPL_WELCOME received over WebSocket");
}

/// Permissive certificate verifier for the test client only.
mod danger {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAny(Arc<CryptoProvider>);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    pub(crate) fn client_config() -> ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth()
    }
}
