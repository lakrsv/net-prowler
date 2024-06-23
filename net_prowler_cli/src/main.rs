use std::time::Duration;

use cidr::IpCidr;
use clap::Parser;
use net_prowler_scanner::tcp_scan_cidr;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    cidr: IpCidr,
    #[arg(long)]
    from_port: u16,
    #[arg(long)]
    to_port: u16,
    #[arg(short, long, default_value = "1500")]
    timeout: u32,
    #[arg(short, long, default_value = "4500")]
    batch_size: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!(
        "Scanning {} with port range {}:{}",
        args.cidr, args.from_port, args.to_port
    );
    let now = Instant::now();
    tcp_scan_cidr(
        args.cidr,
        args.from_port,
        args.to_port,
        Duration::from_millis(args.timeout.into()),
        args.batch_size,
    )
    .await;

    let elapsed = now.elapsed();
    println!(
        "Finished scanning {} with port range {}:{}. Elapsed time: {:.2?}",
        args.cidr, args.from_port, args.to_port, elapsed
    )
}
