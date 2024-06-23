use cidr::{IpCidr, IpInet};
use futures::StreamExt;
use itertools::iproduct;
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct ScanResult {
    ip: IpInet,
    port: u16,
    open: bool,
}

impl ScanResult {
    pub fn new(ip: IpInet, port: u16, open: bool) -> Self {
        Self { ip, port, open }
    }
}

pub async fn tcp_scan_cidr(
    cidr: IpCidr,
    from_port: u16,
    to_port: u16,
    timeout: Duration,
    batch_size: u16,
) {
    let mut futures = futures::stream::iter(iproduct!(cidr.iter(), from_port..to_port))
        .map(|(ip, port)| tcp_scan(ip, port, timeout))
        .buffer_unordered(batch_size as usize);

    while let Some(res) = futures.next().await {
        if res.open {
            println!("{:?}", res)
        }
    }
}

pub async fn tcp_scan(ip: IpInet, port: u16, timeout: Duration) -> ScanResult {
    tokio::time::timeout(
        timeout,
        TcpStream::connect(ip.to_string() + ":" + &port.to_string()),
    )
    .await
    .map_or(ScanResult::new(ip, port, false), |res| {
        res.map_or(ScanResult::new(ip, port, false), |_ok| {
            ScanResult::new(ip, port, true)
        })
    })
}
