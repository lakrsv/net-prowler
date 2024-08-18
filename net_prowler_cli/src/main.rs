use std::time::Duration;

use cidr::{IpCidr, IpInet};
use clap::Parser;
use futures_util::StreamExt;
use net_prowler_scanner::tcp_scan_cidr;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    source: IpInet,
    #[arg(long)]
    target: IpCidr,
    #[arg(long)]
    from_port: u16,
    #[arg(long)]
    to_port: u16,
    #[arg(long, default_value = "1500")]
    timeout: u32,
    #[arg(long, default_value = "4500")]
    batch_size: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!(
        "Scanning {} with port range {}:{}",
        args.target, args.from_port, args.to_port
    );
    let now = Instant::now();
    let mut rx = tcp_scan_cidr(
        args.source,
        args.target,
        args.from_port,
        args.to_port,
        Duration::from_millis(args.timeout.into()),
        args.batch_size,
    )
    .await;

    while let Some(result) = rx.next().await {
        if result.open {
            println!("Got open port {:?}:{:?}", result.ip, result.port);
        }
    }

    let elapsed = now.elapsed();
    println!(
        "Finished scanning {} with port range {}:{}. Elapsed time: {:.2?}",
        args.target, args.from_port, args.to_port, elapsed
    )
}
