use std::{collections::HashMap, io};

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants::{AF_INET, AF_INET6, IPPROTO_TCP},
    inet::{nlas::Nla, ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket as NetlinkSocket, SocketAddr};
use procfs::process::FDTarget;

use crate::{
    network::{BufferFill, Connection, LocalSocket, Protocol, Socket, TcpBufferFill},
    os::ProcessInfo,
    OpenSockets,
};

pub(crate) fn get_open_sockets() -> OpenSockets {
    let mut open_sockets = HashMap::new();
    let mut inode_to_proc = HashMap::new();

    if let Ok(all_procs) = procfs::process::all_processes() {
        for process in all_procs.filter_map(|res| res.ok()) {
            let Ok(fds) = process.fd() else { continue };
            let Ok(stat) = process.stat() else { continue };
            let proc_name = stat.comm;
            let proc_info = ProcessInfo::new(&proc_name, stat.pid as u32);
            for fd in fds.filter_map(|res| res.ok()) {
                if let FDTarget::Socket(inode) = fd.target {
                    inode_to_proc.insert(inode, proc_info.clone());
                }
            }
        }
    }

    macro_rules! insert_proto {
        ($source: expr, $proto: expr) => {
            let entries = $source.into_iter().filter_map(|res| res.ok()).flatten();
            for entry in entries {
                if let Some(proc_info) = inode_to_proc.get(&entry.inode) {
                    let socket = LocalSocket {
                        ip: entry.local_address.ip(),
                        port: entry.local_address.port(),
                        protocol: $proto,
                    };
                    open_sockets.insert(socket, proc_info.clone());
                }
            }
        };
    }

    insert_proto!([procfs::net::tcp(), procfs::net::tcp6()], Protocol::Tcp);
    insert_proto!([procfs::net::udp(), procfs::net::udp6()], Protocol::Udp);

    OpenSockets {
        sockets_to_procs: open_sockets,
        tcp_connections_to_buffer_fill: get_tcp_connections_to_buffer_fill(),
    }
}

fn get_tcp_connections_to_buffer_fill() -> HashMap<Connection, TcpBufferFill> {
    let mut socket = match NetlinkSocket::new(NETLINK_SOCK_DIAG) {
        Ok(socket) => socket,
        Err(_) => return HashMap::new(),
    };
    if socket.bind_auto().is_err() {
        return HashMap::new();
    }
    if socket.connect(&SocketAddr::new(0, 0)).is_err() {
        return HashMap::new();
    }

    let mut fills = HashMap::new();
    for family in [AF_INET, AF_INET6] {
        let Ok(family_fills) = dump_tcp_buffer_fill_for_family(&socket, family) else {
            continue;
        };
        fills.extend(family_fills);
    }
    fills
}

fn dump_tcp_buffer_fill_for_family(
    socket: &NetlinkSocket,
    family: u8,
) -> io::Result<HashMap<Connection, TcpBufferFill>> {
    let request = SockDiagMessage::InetRequest(InetRequest {
        family,
        protocol: IPPROTO_TCP,
        extensions: ExtensionFlags::SKMEMINFO,
        states: StateFlags::all(),
        socket_id: match family {
            AF_INET => SocketId::new_v4(),
            AF_INET6 => SocketId::new_v6(),
            _ => panic!("unsupported inet diag family: {family}"),
        },
    });
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(header, request.into());
    packet.finalize();

    let mut request_buffer = vec![0; packet.buffer_len()];
    assert_eq!(request_buffer.len(), packet.buffer_len());
    packet.serialize(&mut request_buffer);
    socket.send(&request_buffer, 0)?;

    let mut fills = HashMap::new();
    let mut receive_buffer = vec![0; 16 * 1024];
    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0)?;
        let mut offset = 0;
        while offset < size {
            let bytes = &receive_buffer[offset..size];
            let response_packet =
                NetlinkMessage::<SockDiagMessage>::deserialize(bytes).map_err(io::Error::other)?;
            let response_len = response_packet.header.length as usize;
            assert!(
                response_len > 0,
                "sock diag returned a zero-length response"
            );

            match response_packet.payload {
                NetlinkPayload::Done(_) => return Ok(fills),
                NetlinkPayload::Error(error) => {
                    return Err(io::Error::other(format!(
                        "sock diag returned an error: {error:?}"
                    )));
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    if let Some(fill) = tcp_buffer_fill_from_response(&response) {
                        fills.insert(connection_from_socket_id(&response.header.socket_id), fill);
                    }
                }
                NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => {}
                NetlinkPayload::InnerMessage(_) => {}
                _ => {}
            }

            offset += response_len;
        }
    }
}

fn tcp_buffer_fill_from_response(response: &InetResponse) -> Option<TcpBufferFill> {
    response.nlas.iter().find_map(|nla| match nla {
        Nla::MemInfo(mem_info) => tcp_buffer_fill_from_socket_queues(
            response.header.send_queue,
            response.header.recv_queue,
            mem_info.send_queue_max,
            mem_info.receive_queue_max,
        ),
        _ => None,
    })
}

fn tcp_buffer_fill_from_socket_queues(
    send_queue: u32,
    receive_queue: u32,
    send_queue_max: u32,
    receive_queue_max: u32,
) -> Option<TcpBufferFill> {
    let snd = BufferFill::try_new(send_queue, send_queue_max);
    let rcv = BufferFill::try_new(receive_queue, receive_queue_max);
    match (snd, rcv) {
        (None, None) => None,
        _ => Some(TcpBufferFill::new(snd, rcv)),
    }
}

fn connection_from_socket_id(socket_id: &SocketId) -> Connection {
    Connection {
        remote_socket: Socket {
            ip: socket_id.destination_address,
            port: socket_id.destination_port,
        },
        local_socket: LocalSocket {
            ip: socket_id.source_address,
            port: socket_id.source_port,
            protocol: Protocol::Tcp,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::network::{BufferFill, TcpBufferFill};

    use super::tcp_buffer_fill_from_socket_queues;

    #[test]
    fn tcp_buffer_fill_uses_live_queue_sizes_as_numerator() {
        let fill = tcp_buffer_fill_from_socket_queues(25, 10, 100, 50);

        assert_eq!(
            fill,
            Some(TcpBufferFill::new(
                BufferFill::try_new(25, 100),
                BufferFill::try_new(10, 50),
            ))
        );
    }
}
