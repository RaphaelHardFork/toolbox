use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{
    model::{Port, Subdomain},
    SOCKET_CON_TIMEOUT_MS,
};

pub const MOST_COMMON_PORTS_100: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

pub fn scan_ports(mut subdomain: Subdomain) -> Subdomain {
    println!("Scanning ports for {:?}", &subdomain.domain);
    let socket_addresses: Vec<SocketAddr> = format!("{}:1024", subdomain.domain)
        .to_socket_addrs()
        .expect("port scanner: Creating socket address")
        .collect();

    if socket_addresses.is_empty() {
        return subdomain;
    }

    subdomain.open_ports = MOST_COMMON_PORTS_100
        .par_iter()
        .map(|port| scan_port(socket_addresses[0], *port))
        .filter(|port| port.is_open)
        .collect();

    subdomain
}

pub fn scan_port(mut socket_address: SocketAddr, port: u16) -> Port {
    let timeout = Duration::from_millis(SOCKET_CON_TIMEOUT_MS);
    socket_address.set_port(port);

    let is_open = if TcpStream::connect_timeout(&socket_address, timeout).is_ok() {
        true
    } else {
        false
    };

    Port { port, is_open }
}
