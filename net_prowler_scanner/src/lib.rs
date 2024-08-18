use cidr::{Inet, IpCidr, IpInet, Ipv4Inet};
use etherparse::err::{ip, ipv4};
use etherparse::{
    ip_number, Ipv4Header, PacketBuilder, SlicedPacket, TcpHeader, TcpHeaderSlice,
    TcpOptionElement, TcpOptions, TcpSlice,
};
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::executor::ThreadPool;
use futures::{SinkExt, StreamExt, TryFutureExt, TryStreamExt};
use itertools::iproduct;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::task::JoinError;

#[derive(Debug)]
pub struct StartScanResult {
    ip: IpInet,
    port: u16,
    // TODO: Don't use port as seq number
    sequence_number: u32,
}

impl StartScanResult {
    pub fn new(ip: IpInet, port: u16, sequence_number: u32) -> Self {
        Self {
            ip,
            port,
            sequence_number,
        }
    }
}

pub struct ScanResult {
    pub ip: IpInet,
    pub port: u16,
    pub open: bool,
}

impl ScanResult {
    pub fn new(ip: IpInet, port: u16, open: bool) -> Self {
        Self { ip, port, open }
    }
}

// complete handshake example in c++ https://github.com/MaxXor/raw-sockets-example/blob/master/rawsockets.c
pub async fn tcp_scan_cidr(
    source: IpInet,
    target: IpCidr,
    from_port: u16,
    mut to_port: u16,
    timeout: Duration,
    batch_size: u16,
) -> Receiver<ScanResult> {
    let socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .expect("Failed opening socket");

    socket
        .set_header_included(true)
        .expect("Failed setting socket to header included");

    if to_port >= 65535 {
        to_port = 65534;
    }

    let shared_socket: Arc<Socket> = Arc::new(socket);

    let listen_socket = shared_socket.clone();
    let (mut tx, mut rx): (Sender<ScanResult>, Receiver<ScanResult>) = mpsc::channel(65535);
    tokio::task::spawn(async move {
        loop {
            let mut buffer: [u8; 4096] = [0; 4096];
            let buffer =
                unsafe { &mut *(&mut buffer as *mut [u8; 4096] as *mut [MaybeUninit<u8>; 4096]) };

            match listen_socket.recv_from(buffer) {
                Ok(response) => {
                    let buffer =
                        unsafe { *(buffer as *mut [MaybeUninit<u8>; 4096] as *mut [u8; 4096]) };
                    let frame = buffer[..response.0].to_vec();

                    match SlicedPacket::from_ip(frame.as_slice()) {
                        Err(value) => {
                            println!("Err {:?}", value);
                        }
                        Ok(value) => match value.transport {
                            None => {
                                println!("No transport");
                            }
                            Some(value) => match value {
                                etherparse::TransportSlice::Tcp(frame) => {
                                    match TcpHeaderSlice::from_slice(frame.header_slice()) {
                                        Err(header) => {
                                            println!("Err {:?}", header);
                                        }
                                        Ok(header) => {
                                            if header.syn() && header.ack() {
                                                tx.try_send(ScanResult::new(
                                                    source,
                                                    frame.source_port(),
                                                    true,
                                                ))
                                                .unwrap();
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    println!("Packet did not contain TcpSlice");
                                }
                            },
                        },
                    }
                }
                Err(_err) => continue,
            };
        }
    });

    let mut tasks = futures::stream::iter(iproduct!(target.iter(), from_port..to_port + 1))
        .map(|(ip, port)| {
            let thread_socket = shared_socket.clone();
            tokio::task::spawn(
                async move { tcp_scan(&thread_socket, source, ip, port, timeout).await },
            )
        })
        .buffer_unordered(batch_size as usize);
    while let Some(_) = tasks.next().await {}

    rx
}

// see https://github.com/JuxhinDB/synner/blob/master/src/tcp.rs
pub async fn tcp_scan(
    socket: &Socket,
    source: IpInet,
    target: IpInet,
    port: u16,
    timeout: Duration,
) {
    println!(
        "Scanning {:?}:{:?} from {:?}",
        target,
        port,
        thread::current()
    );
    let source_ipv4 = match source {
        IpInet::V4(ip) => ip,
        _ => panic!("Expected local IPV4"),
    };
    let target_ipv4 = match target {
        IpInet::V4(ip) => ip,
        _ => panic!("Expected target IPV4"),
    };
    let syn = create_tcp_syn(source_ipv4, target_ipv4, port, port as u32);
    let addr = SocketAddr::new(target.address(), port);

    socket
        .send_to(syn.as_slice(), &SockAddr::from(addr))
        .expect("Failed sending data");
}

// loook at https://github.com/JuxhinDB/synner/blob/master/src/tcp.rs
pub fn create_tcp_syn(
    source: Ipv4Inet,
    destination: Ipv4Inet,
    port: u16,
    sequence_number: u32,
) -> Vec<u8> {
    let builder = PacketBuilder::ip(etherparse::IpHeaders::Ipv4(
        Ipv4Header::new(
            0,
            255,
            ip_number::TCP,
            source.address().octets(),
            destination.address().octets(),
        )
        .unwrap(),
        Default::default(),
    ))
    .tcp(52114, port, sequence_number, 64240)
    .syn();

    let payload = Vec::<u8>::with_capacity(0);
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, &payload).unwrap();
    result
}
