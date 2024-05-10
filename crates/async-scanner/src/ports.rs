use crate::model::{Port, Subdomain};
use crate::SOCKET_CON_TIMEOUT_MS;
use futures::StreamExt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::{net::TcpStream, sync::mpsc};

pub const MOST_COMMON_PORTS_100: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

pub async fn scan_ports(concurrency: usize, mut subdomain: Subdomain) -> Subdomain {
    println!("Scanning ports for {:?}", &subdomain.domain);
    let socket_addresses: Vec<SocketAddr> = format!("{}:1024", subdomain.domain)
        .to_socket_addrs()
        .expect("port scanner: Creating socket address")
        .collect();

    if socket_addresses.is_empty() {
        return subdomain;
    }
    let socket_address = socket_addresses[0];

    // create 2 channels, one for enumerate ports and the other to
    // execute scan_port and collect the result
    let (input_tx, input_rx) = mpsc::channel(concurrency);
    let (output_tx, output_rx) = mpsc::channel(concurrency);

    // send each port number into the first channel
    tokio::spawn(async move {
        for port in MOST_COMMON_PORTS_100 {
            let _ = input_tx.send(*port).await;
        }
    });

    // create a stream that push the port number into the `scan_port` function and
    // push it to the second channel
    let input_rx_stream = tokio_stream::wrappers::ReceiverStream::new(input_rx);
    input_rx_stream
        .for_each_concurrent(concurrency, |port| {
            let output_tx = output_tx.clone();
            async move {
                let port = scan_port(socket_address, port).await;
                if port.is_open {
                    let _ = output_tx.send(port).await;
                }
            }
        })
        .await;
    drop(output_tx);

    // collect results from the second channel
    let output_rx_stream = tokio_stream::wrappers::ReceiverStream::new(output_rx);
    subdomain.open_ports = output_rx_stream.collect().await;

    subdomain
}

async fn scan_port(mut socker_address: SocketAddr, port: u16) -> Port {
    let timeout = Duration::from_millis(SOCKET_CON_TIMEOUT_MS);
    socker_address.set_port(port);

    let is_open = matches!(
        tokio::time::timeout(timeout, TcpStream::connect(&socker_address)).await,
        Ok(Ok(_))
    );

    Port { port, is_open }
}
