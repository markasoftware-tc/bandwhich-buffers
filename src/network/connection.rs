use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
};

#[derive(PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Debug, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    #[allow(dead_code)]
    pub fn from_str(string: &str) -> Option<Self> {
        match string {
            "TCP" => Some(Protocol::Tcp),
            "UDP" => Some(Protocol::Udp),
            _ => None,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct BufferFill {
    used: u32,
    capacity: NonZeroU32,
}

impl BufferFill {
    pub fn try_new(used: u32, capacity: u32) -> Option<Self> {
        Some(Self {
            used,
            capacity: NonZeroU32::new(capacity)?,
        })
    }

    pub fn fullness_percentage(self) -> u16 {
        ((u128::from(self.used) * 100) / u128::from(self.capacity.get()))
            .try_into()
            .unwrap()
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct TcpBufferFill {
    pub snd: Option<BufferFill>,
    pub rcv: Option<BufferFill>,
}

impl TcpBufferFill {
    pub fn new(snd: Option<BufferFill>, rcv: Option<BufferFill>) -> Self {
        assert!(
            snd.is_some() || rcv.is_some(),
            "tcp buffer fill must have at least one populated side"
        );
        Self { snd, rcv }
    }
}

impl fmt::Display for TcpBufferFill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snd = self
            .snd
            .map(|fill| format!("{}%", fill.fullness_percentage()))
            .unwrap_or_else(|| "--".to_string());
        let rcv = self
            .rcv
            .map(|fill| format!("{}%", fill.fullness_percentage()))
            .unwrap_or_else(|| "--".to_string());

        write!(f, "{snd}/{rcv}")
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Copy)]
pub struct Socket {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Socket { ip, port } = self;
        match ip {
            IpAddr::V4(v4) => write!(f, "{v4}:{port}"),
            IpAddr::V6(v6) => write!(f, "[{v6}]:{port}"),
        }
    }
}

#[derive(PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub struct LocalSocket {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

impl fmt::Debug for LocalSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let LocalSocket { ip, port, protocol } = self;
        match ip {
            IpAddr::V4(v4) => write!(f, "{protocol}://{v4}:{port}"),
            IpAddr::V6(v6) => write!(f, "{protocol}://[{v6}]:{port}"),
        }
    }
}

#[derive(PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub struct Connection {
    pub remote_socket: Socket,
    pub local_socket: LocalSocket,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Connection {
            remote_socket,
            local_socket,
        } = self;
        write!(f, "{local_socket:?} => {remote_socket:?}")
    }
}

pub fn display_ip_or_host(ip: IpAddr, ip_to_host: &HashMap<IpAddr, String>) -> String {
    match ip_to_host.get(&ip) {
        Some(host) => host.clone(),
        None => ip.to_string(),
    }
}

pub fn display_connection_string(
    connection: &Connection,
    ip_to_host: &HashMap<IpAddr, String>,
    interface_name: &str,
) -> String {
    format!(
        "<{interface_name}>:{} => {}:{} ({})",
        connection.local_socket.port,
        display_ip_or_host(connection.remote_socket.ip, ip_to_host),
        connection.remote_socket.port,
        connection.local_socket.protocol,
    )
}

pub fn display_tcp_buffer_fill(
    connection: &Connection,
    tcp_buffer_fill: Option<TcpBufferFill>,
) -> String {
    match connection.local_socket.protocol {
        Protocol::Tcp => tcp_buffer_fill
            .map(|fill| fill.to_string())
            .unwrap_or_else(|| "--/--".to_string()),
        Protocol::Udp => "--/--".to_string(),
    }
}

impl Connection {
    pub fn new(
        remote_socket: SocketAddr,
        local_ip: IpAddr,
        local_port: u16,
        protocol: Protocol,
    ) -> Self {
        Connection {
            remote_socket: Socket {
                ip: remote_socket.ip(),
                port: remote_socket.port(),
            },
            local_socket: LocalSocket {
                ip: local_ip,
                port: local_port,
                protocol,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv4Addr};

    use super::{
        display_connection_string, display_tcp_buffer_fill, BufferFill, Connection, Protocol,
        TcpBufferFill,
    };

    #[test]
    fn display_connection_string_stays_focused_on_endpoints() {
        let connection = Connection::new(
            (Ipv4Addr::new(1, 1, 1, 1), 12345).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            443,
            Protocol::Tcp,
        );

        let rendered = display_connection_string(&connection, &HashMap::new(), "eth0");

        assert_eq!(rendered, "<eth0>:443 => 1.1.1.1:12345 (tcp)");
    }

    #[test]
    fn display_tcp_buffer_fill_formats_tcp_percentages() {
        let connection = Connection::new(
            (Ipv4Addr::new(1, 1, 1, 1), 12345).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            443,
            Protocol::Tcp,
        );

        let rendered = display_tcp_buffer_fill(
            &connection,
            Some(TcpBufferFill::new(
                BufferFill::try_new(50, 100),
                BufferFill::try_new(25, 100),
            )),
        );

        assert_eq!(rendered, "50%/25%");
    }

    #[test]
    fn display_tcp_buffer_fill_uses_placeholder_for_udp() {
        let connection = Connection::new(
            (Ipv4Addr::new(1, 1, 1, 1), 12345).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            443,
            Protocol::Udp,
        );

        let rendered = display_tcp_buffer_fill(&connection, None);

        assert_eq!(rendered, "--/--");
    }
}
