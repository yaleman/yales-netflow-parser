#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]

use clap::Parser;
use std::collections::BTreeMap;
use std::io;
use tokio::net::UdpSocket;

use netflow_parser::{NetflowPacket, NetflowParser};

use yales_netflow_parser::{CliOpts, handle_flowset};

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut parsers: BTreeMap<String, NetflowParser> = BTreeMap::new();
    let opts = CliOpts::parse();
    let sock = UdpSocket::bind(format!("{}:{}", opts.bind_address, opts.port)).await?;

    let mut buf = [0; 1024 * 64]; // Adjust buffer size as needed

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        let data = buf[..len].to_vec();

        let result = match parsers.get_mut(&addr.to_string()) {
            Some(parser) => parser.parse_bytes(data.as_slice()),
            None => {
                let mut new_parser = NetflowParser::default();
                let result = new_parser.parse_bytes(data.as_slice());
                parsers.insert(addr.to_string(), new_parser);
                result
            }
        };

        if let Some(error) = result.error
            && opts.debug
        {
            eprintln!("Error parsing packet from {addr}: {error:?}");
        }
        for packet in result.packets {
            match packet {
                NetflowPacket::V9(packet) => {
                    for flowset in packet.flowsets {
                        handle_flowset(&opts, packet.header.unix_secs.into(), &addr, flowset);
                    }
                }
                _ => {
                    if opts.debug {
                        eprintln!("Unsupported packet type received from {addr}: {packet:?}");
                    }
                }
            }
        }
    }
}
