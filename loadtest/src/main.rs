//! ferrixd load generator.
//!
//! Opens a large number of concurrent IRC connections, registers each, joins a
//! shared channel, and holds the connections open so the server's resource use
//! (RSS, task count) can be measured externally.
//!
//! Because a single (src_ip, dst) pair is limited to ~28k ephemeral ports, the
//! generator spreads its sockets across several loopback source addresses
//! (127.0.0.1, 127.0.0.2, …) to get past that ceiling.
//!
//! Usage:
//!   loadtest <host:port> <count> [src_ips] [hold_secs] [chan_bucket]
//!
//! `chan_bucket` groups clients into channels of that size (client `id` joins
//! `#load{id / bucket}`); 0 skips joining. Grouping keeps channel fan-out bounded
//! so a density run doesn't turn into an O(N^2) broadcast storm.
//!
//! Example: loadtest 127.0.0.1:6667 100000 4 30 100

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpSocket;
use tokio::sync::Semaphore;

struct Stats {
    connected: AtomicU64,
    registered: AtomicU64,
    joined: AtomicU64,
    failed: AtomicU64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr: SocketAddr = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("127.0.0.1:6667")
        .parse()
        .expect("host:port");
    let count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let src_ips: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let hold_secs: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(20);
    let chan_bucket: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Cap concurrent in-flight handshakes so we don't overflow the listen backlog.
    let gate = Arc::new(Semaphore::new(8_000));
    let stats = Arc::new(Stats {
        connected: AtomicU64::new(0),
        registered: AtomicU64::new(0),
        joined: AtomicU64::new(0),
        failed: AtomicU64::new(0),
    });

    println!(
        "connecting {count} clients to {addr} across {src_ips} source IP(s), holding {hold_secs}s"
    );
    let start = Instant::now();
    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        let src = Ipv4Addr::new(127, 0, 0, (1 + (i % src_ips)) as u8);
        let gate_c = gate.clone();
        let stats_c = stats.clone();
        handles.push(tokio::spawn(async move {
            let permit = gate_c.acquire_owned().await.expect("semaphore");
            match client(addr, src, i, chan_bucket, &stats_c).await {
                Ok((reader, writer)) => {
                    drop(permit); // handshake done; free a slot for the next client
                    hold(reader, writer, hold_secs).await;
                }
                Err(_) => {
                    stats_c.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
        if i % 5_000 == 0 && i > 0 {
            // Give the ramp a moment and report progress.
            tokio::time::sleep(Duration::from_millis(50)).await;
            report(&stats, i, start);
        }
    }

    // Wait until everything settles (registered + failed == count) or a timeout.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let done = stats.registered.load(Ordering::Relaxed) + stats.failed.load(Ordering::Relaxed);
        if done as usize >= count || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let elapsed = start.elapsed();
    let reg = stats.registered.load(Ordering::Relaxed);
    println!("\n=== established ===");
    report(&stats, count, start);
    if elapsed.as_secs_f64() > 0.0 {
        println!("rate: {:.0} registrations/sec", reg as f64 / elapsed.as_secs_f64());
    }
    println!("holding {hold_secs}s for measurement...");

    // Keep the connections open for the hold window.
    for h in handles {
        let _ = h.await;
    }
    println!("done.");
}

fn report(stats: &Stats, attempted: usize, start: Instant) {
    println!(
        "  t={:>5.1}s attempted={attempted:>7} connected={:>7} registered={:>7} joined={:>7} failed={:>6}",
        start.elapsed().as_secs_f64(),
        stats.connected.load(Ordering::Relaxed),
        stats.registered.load(Ordering::Relaxed),
        stats.joined.load(Ordering::Relaxed),
        stats.failed.load(Ordering::Relaxed),
    );
}

type Conn = (BufReader<OwnedReadHalf>, OwnedWriteHalf);

async fn client(
    addr: SocketAddr,
    src: Ipv4Addr,
    id: usize,
    chan_bucket: usize,
    stats: &Stats,
) -> std::io::Result<Conn> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(IpAddr::V4(src), 0))?;
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true).ok();
    stats.connected.fetch_add(1, Ordering::Relaxed);

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    wr.write_all(format!("NICK l{id}\r\nUSER l{id} 0 * :load\r\n").as_bytes())
        .await?;

    // Read until we see the welcome numeric (001) or registration fails.
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"));
        }
        if line.contains(" 001 ") {
            stats.registered.fetch_add(1, Ordering::Relaxed);
            break;
        }
        if line.contains(" 433 ") || line.contains(" 432 ") {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "nick rejected"));
        }
    }

    // Optionally join a bucketed channel and wait for end-of-names (366).
    if chan_bucket > 0 {
        wr.write_all(format!("JOIN #load{}\r\n", id / chan_bucket).as_bytes())
            .await?;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"));
            }
            if line.contains(" 366 ") {
                stats.joined.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    Ok((reader, wr))
}

async fn hold(mut reader: BufReader<OwnedReadHalf>, mut writer: OwnedWriteHalf, secs: u64) {
    // Drain the socket so the server's send queue never backs up, and answer any
    // PING so the connection survives the hold window.
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match tokio::time::timeout(Duration::from_millis(500), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break, // server closed
            Ok(Ok(_)) => {
                if let Some(token) = line.strip_prefix("PING ") {
                    let _ = writer
                        .write_all(format!("PONG {}", token.trim_start_matches(':')).as_bytes())
                        .await;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {} // idle tick
        }
    }
    drop(writer);
}
