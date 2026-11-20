use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V1_MAX: usize = 107;
const V2_MAX_PAYLOAD: usize = 4096;
pub(crate) const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    V1,
    V2,
}

impl FromStr for Version {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            _ => Err("proxy_protocol expects v1 or v2"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Addresses {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl Addresses {
    fn canonical(self) -> Self {
        Self {
            source: SocketAddr::new(self.source.ip().to_canonical(), self.source.port()),
            destination: SocketAddr::new(
                self.destination.ip().to_canonical(),
                self.destination.port(),
            ),
        }
    }
}

pub(crate) async fn read(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Addresses>> {
    match stream.read_u8().await? {
        b'P' => read_v1(stream).await,
        b'\r' => read_v2(stream).await,
        _ => Err(invalid("missing PROXY protocol header")),
    }
}

async fn read_v1(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Addresses>> {
    let mut line = [0; V1_MAX];
    line[0] = b'P';
    for end in 1..line.len() {
        line[end] = stream.read_u8().await?;
        if line[end] != b'\n' {
            continue;
        }
        let line = line[..=end]
            .strip_suffix(b"\r\n")
            .ok_or_else(|| invalid("invalid PROXY v1 line ending"))?;
        if !line.iter().all(|byte| (b' '..=b'~').contains(byte)) {
            return Err(invalid("invalid PROXY v1 characters"));
        }
        let line = std::str::from_utf8(line).map_err(|_| invalid("invalid PROXY v1 characters"))?;
        let body = line
            .strip_prefix("PROXY ")
            .ok_or_else(|| invalid("invalid PROXY v1 signature"))?;
        let mut fields = body.split(' ');
        let family = fields.next().unwrap_or_default();
        if family == "UNKNOWN" {
            return Ok(None);
        }
        let mut address = || {
            let addr = fields
                .next()
                .and_then(|addr| addr.parse().ok())
                .ok_or_else(|| invalid("invalid PROXY v1 address"))?;
            Ok::<_, io::Error>(addr)
        };
        let src = address()?;
        let dst = address()?;
        if !matches!(
            (family, src, dst),
            ("TCP4", std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                | ("TCP6", std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
        ) {
            return Err(invalid("invalid PROXY v1 address family"));
        }
        let mut port = || {
            fields
                .next()
                .filter(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|port| port.parse().ok())
                .ok_or_else(|| invalid("invalid PROXY v1 port"))
        };
        let source = SocketAddr::new(src, port()?);
        let destination = SocketAddr::new(dst, port()?);
        if fields.next().is_some() {
            return Err(invalid("extra PROXY v1 fields"));
        }
        return Ok(Some(
            Addresses {
                source,
                destination,
            }
            .canonical(),
        ));
    }
    Err(invalid("PROXY v1 header too long"))
}

async fn read_v2(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Addresses>> {
    let mut fixed = [0; 15];
    stream.read_exact(&mut fixed).await?;
    if fixed[..11] != V2_SIGNATURE[1..] || !matches!(fixed[11], 0x20 | 0x21) {
        return Err(invalid("invalid PROXY v2 signature or command"));
    }
    let length = usize::from(u16::from_be_bytes([fixed[13], fixed[14]]));
    if length > V2_MAX_PAYLOAD {
        return Err(invalid("PROXY v2 header too long"));
    }
    let mut payload = [0; V2_MAX_PAYLOAD];
    let payload = &mut payload[..length];
    stream.read_exact(payload).await?;
    if fixed[11] == 0x20 || fixed[12] == 0 {
        return Ok(None);
    }
    let port = |i| u16::from_be_bytes([payload[i], payload[i + 1]]);
    let (source, destination) = match fixed[12] {
        0x11 if length >= 12 => (
            SocketAddr::new(
                Ipv4Addr::from(<[u8; 4]>::try_from(&payload[..4]).unwrap()).into(),
                port(8),
            ),
            SocketAddr::new(
                Ipv4Addr::from(<[u8; 4]>::try_from(&payload[4..8]).unwrap()).into(),
                port(10),
            ),
        ),
        0x21 if length >= 36 => (
            SocketAddr::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16]).unwrap()).into(),
                port(32),
            ),
            SocketAddr::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[16..32]).unwrap()).into(),
                port(34),
            ),
        ),
        _ => return Err(invalid("unsupported or truncated PROXY v2 address")),
    };
    Ok(Some(
        Addresses {
            source,
            destination,
        }
        .canonical(),
    ))
}

pub(crate) async fn write(
    stream: &mut (impl AsyncWrite + Unpin),
    version: Version,
    addresses: Option<Addresses>,
) -> io::Result<()> {
    let addresses = addresses
        .map(Addresses::canonical)
        .filter(|addr| addr.source.is_ipv4() == addr.destination.is_ipv4());
    match (version, addresses) {
        (Version::V1, Some(addr)) => {
            let family = if addr.source.is_ipv4() {
                "TCP4"
            } else {
                "TCP6"
            };
            let header = format!(
                "PROXY {family} {} {} {} {}\r\n",
                addr.source.ip(),
                addr.destination.ip(),
                addr.source.port(),
                addr.destination.port()
            );
            stream.write_all(header.as_bytes()).await
        }
        (Version::V1, None) => stream.write_all(b"PROXY UNKNOWN\r\n").await,
        (Version::V2, addresses) => {
            let mut header = [0; 52];
            header[..12].copy_from_slice(V2_SIGNATURE);
            header[12] = 0x21;
            let length = match addresses.map(|addr| (addr.source.ip(), addr.destination.ip(), addr))
            {
                Some((std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst), addr)) => {
                    header[13..16].copy_from_slice(&[0x11, 0, 12]);
                    header[16..20].copy_from_slice(&src.octets());
                    header[20..24].copy_from_slice(&dst.octets());
                    header[24..26].copy_from_slice(&addr.source.port().to_be_bytes());
                    header[26..28].copy_from_slice(&addr.destination.port().to_be_bytes());
                    28
                }
                Some((std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst), addr)) => {
                    header[13..16].copy_from_slice(&[0x21, 0, 36]);
                    header[16..32].copy_from_slice(&src.octets());
                    header[32..48].copy_from_slice(&dst.octets());
                    header[48..50].copy_from_slice(&addr.source.port().to_be_bytes());
                    header[50..52].copy_from_slice(&addr.destination.port().to_be_bytes());
                    52
                }
                _ => 16,
            };
            stream.write_all(&header[..length]).await
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
