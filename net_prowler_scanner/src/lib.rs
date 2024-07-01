use cidr::{Inet, IpCidr, IpInet, Ipv4Inet};
use etherparse::err::ipv4;
use etherparse::{
    ip_number, Ipv4Header, PacketBuilder, SlicedPacket, TcpHeader, TcpHeaderSlice, TcpOptionElement, TcpOptions, TcpSlice
};
use futures::StreamExt;
use itertools::iproduct;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, TcpListener};
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

// complete handshake example in c++ https://github.com/MaxXor/raw-sockets-example/blob/master/rawsockets.c
pub async fn tcp_scan_cidr(
    cidr: IpCidr,
    from_port: u16,
    to_port: u16,
    timeout: Duration,
    batch_size: u16,
) {
    let socket = Socket::new_raw(Domain::IPV4, Type::RAW, None)
    .expect("Failed opening socket");
    socket
        .set_only_v6(false)
        .expect("Failed setting socket to allow TCP");

    // socket
    //     .set_nonblocking(true)
    //     .expect("Failed setting socket to non-blocking mode");

    // socket
    //     .set_header_included(true)
    //     .expect("Failed setting socket to header included");
    // socket
    //     .set_header_included(true)
    //     .expect("Failed setting socket to header included");

    //let address: SocketAddr = "0.0.0.0:52114".parse().unwrap();
    //socket.bind(&address.into()).unwrap();
    //socket.listen(128).unwrap();
    //dbg!(socket.local_addr().unwrap().as_socket_ipv4().unwrap().ip());

    let mut futures = futures::stream::iter(iproduct!(cidr.iter(), from_port..to_port + 1))
        .map(|(ip, port)| tcp_scan(&socket, ip, port, timeout))
        .buffer_unordered(batch_size as usize);

    while let Some(res) = futures.next().await {
        if res.open {
            println!("{:?}", res)
        }
    }
}

// see https://github.com/JuxhinDB/synner/blob/master/src/tcp.rs
pub async fn tcp_scan(socket: &Socket, ip: IpInet, port: u16, timeout: Duration) -> ScanResult {
    let mut ipv4 = match ip {
        IpInet::V4(ip) => ip,
        _ => panic!("Expected IPV4"),
    };
    let syn = create_tcp_syn(ipv4, port);
    let addr = SocketAddr::new(ip.address(), port);

    dbg!(SlicedPacket::from_ethernet(syn.as_slice()).unwrap());

    socket
    .send_to(syn.as_slice(), &SockAddr::from(addr))
    .expect("Failed sending data");

    // socket
    //     .send_to(syn.as_slice(), &SockAddr::from(addr))
    //     .expect("Failed sending data");

    loop {
        //let mut recv_buf: [MaybeUninit<u8>; 4096] = unsafe { MaybeUninit::uninit().assume_init() };
        let mut buffer: [u8; 4096] = [0; 4096];
        let buffer =
            unsafe { &mut *(&mut buffer as *mut [u8; 4096] as *mut [MaybeUninit<u8>; 4096]) };

        let res = match socket.recv_from(buffer) {
            Ok(response) => {
                dbg!(response.1.as_socket_ipv4().unwrap().ip());

                let buffer =
                    unsafe { *(buffer as *mut [MaybeUninit<u8>; 4096] as *mut [u8; 4096]) };
                let frame = buffer[..response.0].to_vec();

                // for b in 0..response.0 {
                //     //dbg!(unsafe{recv_buf[b].assume_init()});
                //     frame[b] = unsafe {recv_buf[b].assume_init()}
                // }
                match SlicedPacket::from_ethernet(frame.as_slice()) {
                    Err(value) => {
                        println!("Err {:?}", value);
                        return ScanResult::new(ip, port, false);
                    }
                    Ok(value) => match value.transport {
                        None => {
                            println!("No transport");
                            return ScanResult::new(ip, port, false);
                        }
                        Some(value) => match value {
                            etherparse::TransportSlice::Tcp(frame) => {
                                println!("acknum? {:?}", frame.acknowledgment_number());
                                println!("seqnum? {:?}", frame.sequence_number());
                                println!("Syn??? {:?}", frame.syn());
                                println!("Ack??? {:?}", frame.ack());
                                match TcpHeaderSlice::from_slice(frame.header_slice()) {
                                    Err(header) => {
                                        println!("Err {:?}", header);
                                        return ScanResult::new(ip, port, false);
                                    }
                                    Ok(header) => {
                                        if header.syn() && header.ack() {
                                            println!("Port is open!");
                                        } else {
                                            println!("Syn? {:?}", header.syn());
                                            println!("Ack? {:?}", header.ack());
                                            println!("Port is not open!");
                                        }
                                    }
                                }
                            }
                            _ => {
                                println!("Packet did not contain TcpSlice");
                                return ScanResult::new(ip, port, false);
                            }
                        },
                    },
                }
            }
            Err(err) => continue,
        };
    }
    ScanResult::new(ip, port, false);

    //socket.send_to(buf, addr)
    // tokio::time::timeout(
    //     timeout,
    //     TcpStream::connect(ip.to_string() + ":" + &port.to_string()),
    // )
    // .await
    // .map_or(ScanResult::new(ip, port, false), |res| {
    //     res.map_or(ScanResult::new(ip, port, false), |_ok| {
    //         ScanResult::new(ip, port, true)
    //     })
    // })
}

// loook at https://github.com/JuxhinDB/synner/blob/master/src/tcp.rs
pub fn create_tcp_syn(destination: Ipv4Inet, port: u16) -> Vec<u8> {

    let builder = PacketBuilder
    ::ethernet2(
        [0x7c, 0xc2, 0xc6, 0x33, 0x45, 0xa7],
    [0xc4, 0xe5, 0x32, 0x29, 0xff, 0x44])
    .ipv4([10, 5, 0, 2], destination.address().octets(), 20)
    // ::ip(etherparse::IpHeaders::Ipv4(Ipv4Header::new(
    //     0, 
    //     255, 
    //     ip_number::TCP, 
    //     [192, 168, 1, 125], 
    //     destination.address().octets()).unwrap(), Default::default()))
        .tcp(52114, port, 123532, 64240)
        .syn();

    // let builder = PacketBuilder::ethernet2(
    //     [0x7c, 0xc2, 0xc6, 0x33, 0x45, 0xa7],
    //     [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    // )
    // .ipv4(
    //     [192, 168, 1, 125],
    //     //[91, 196, 222, 30],
    //     //[91,196,222,28],
    //     //[0; 4],
    //     //[0,0,0,0],
    //     destination.address().octets(),
    //     255,
    // )
    // .tcp(52114, port, 0, 64240)
    // .syn();
    let payload = Vec::<u8>::with_capacity(0);
    //let payload = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, &payload).unwrap();
    result
}

// use rand::prelude::*;
// use std::net::{IpAddr, Ipv4Addr};
// use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
// use pnet_packet::ethernet::{MutableEthernetPacket, EtherTypes};
// use pnet_packet::ip::{IpNextHeaderProtocols};
// use pnet_packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
// use pnet_datalink::{Channel, NetworkInterface, MacAddr};

// pub struct PartialTCPPacketData<'a> {
//     pub destination_ip: Ipv4Addr,
//     pub iface_ip: Ipv4Addr,
//     pub iface_name: &'a String,
//     pub iface_src_mac: &'a MacAddr,
// }


// pub fn build_random_packet(partial_packet: &PartialTCPPacketData, tmp_packet: &mut [u8]) {
//     const ETHERNET_HEADER_LEN: usize = 14;
//     const IPV4_HEADER_LEN: usize = 20;

//     // Setup Ethernet header
//     {
//         let mut eth_header = MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

//         eth_header.set_destination(MacAddr::broadcast());
//         eth_header.set_source(*partial_packet.iface_src_mac);
//         eth_header.set_ethertype(EtherTypes::Ipv4);
//     }

//     // Setup IP header
//     {
//         let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)]).unwrap();
//         ip_header.set_header_length(69);
//         ip_header.set_total_length(52);
//         ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
//         ip_header.set_source(partial_packet.iface_ip);
//         ip_header.set_destination(partial_packet.destination_ip);
//         ip_header.set_identification(rand::random::<u16>());
//         ip_header.set_ttl(64);
//         ip_header.set_version(4);
//         ip_header.set_flags(Ipv4Flags::DontFragment);

//         let checksum = pnet_packet::ipv4::checksum(&ip_header.to_immutable());
//         ip_header.set_checksum(checksum);
//     }

//     // Setup TCP header
//     {
//         let mut tcp_header = MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();

//         tcp_header.set_source(rand::random::<u16>());
//         tcp_header.set_destination(rand::random::<u16>());

//         tcp_header.set_flags(TcpFlags::SYN);
//         tcp_header.set_window(64240);
//         tcp_header.set_data_offset(8);
//         tcp_header.set_urgent_ptr(0);
//         tcp_header.set_sequence(0);

//         tcp_header.set_options(&[TcpOption::mss(1460), TcpOption::sack_perm(),  TcpOption::nop(), TcpOption::nop(), TcpOption::wscale(7)]);

//         let checksum = pnet_packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &partial_packet.iface_ip, &partial_packet.destination_ip);
//         tcp_header.set_checksum(checksum);
//     }
// }

// pub fn send_tcp_packets(destination_ip: Ipv4Addr, interface: String, count: u32) {
//     let interfaces = pnet_datalink::interfaces();

//     println!("List of Available Interfaces\n");

//     for interface in interfaces.iter() {
//         let iface_ip = interface.ips.iter().next().map(|x| match x.ip() {
//             IpAddr::V4(ipv4) => Some(ipv4),
//             _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
//         });

//         println!("Interface name: {:?}\nInterface MAC: {:?}\nInterface IP: {:?}\n", &interface.name, &interface.mac.unwrap(), iface_ip)
//     }

//     let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface;
//     let interface = interfaces
//         .into_iter()
//         .filter(interfaces_name_match)
//         .next()
//         .expect(&format!("could not find interface by name {}", interface));

//     let iface_ip = match interface.ips.iter().nth(0).expect(&format!("the interface {} does not have any IP addresses", interface)).ip() {
//         IpAddr::V4(ipv4) => ipv4,
//         _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
//     };

//     let partial_packet: PartialTCPPacketData = PartialTCPPacketData {
//         destination_ip: destination_ip,
//         iface_ip,
//         iface_name: &interface.name,
//         iface_src_mac: &interface.mac.unwrap(),
//     };

//     let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
//         Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
//         Ok(_) => panic!("Unknown channel type"),
//         Err(e) => panic!("Error happened {}", e),
//     };

//     for i in 0..count {

//         if &i % 10000 == 0 {
//             println!("Sent {:?} packets", &i);
//         }

//         tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
//             build_random_packet(&partial_packet, packet);
//         });
//     }
// }