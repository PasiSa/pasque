use std::{
    any::Any,
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{BytesMut, BufMut};
use futures::{
    FutureExt,
    sink::SinkExt,
    stream::{SplitSink, StreamExt},
};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use octets::Octets;
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    sync::Mutex, task::JoinHandle,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::AsyncDevice;

use super::*;
use crate::{
    client::PsqClient,
    platform::{self, get_os_networking},
    server::Endpoint,
    util::{
        hdrs_to_strings,
        send_quic_packets, 
    },
    PsqError,
};


/// IP tunnel over HTTP/3 connection.
/// Tunnel is associated with an HTTP/3 stream established with
/// CONNECT request.
/// 
/// See [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484) for more information.
pub struct IpTunnel {
    stream_id: u64,
    tunwriter: Option<SplitSink<Framed<AsyncDevice, IpPacketCodec>, BytesMut>>,
    ifname: String,
    tuntask: Option<JoinHandle<Result<(), PsqError>>>,
    addresses: Vec<IpAddr>,

    /// For testing support: tunneled packets are optionally written here
    teststream: Option<tokio::net::UnixStream>,
}

impl IpTunnel {

    /// Connect a new IP tunnel using given HTTP/3 connection, as indicated with
    /// `pconn`. 
    /// 
    /// Sends an HTTP/3 CONNECT request, and if successful, returns the created
    /// IpTunnel object in response that can be used for further tunnel/proxy
    /// operations. Blocks until response to the CONNECT request is processed.
    /// 
    /// `urlstr` is URL path of the IP proxy endpoint at server. It is appended
    /// to the base URL used when establishing connection.
    pub async fn connect<'a>(
        pconn: &'a mut PsqClient,
        urlstr: &str,
        ifname: &str,
    ) -> Result<&'a IpTunnel, PsqError> {

        let url = pconn.get_url().join(urlstr)?;
        let stream_id = start_connection(
            pconn,
            &url,
            "connect-ip",
        ).await?;

        // Blocks until request is replied and tunnel is set up
        let ret = pconn.add_stream(
            stream_id,
            Box::new(IpTunnel {
                stream_id,
                tunwriter: None,
                ifname: ifname.to_string(),
                tuntask: None,
                addresses: Vec::new(),
                teststream: None,
             })
        ).await;
        match ret {
            Ok(stream) => {
                Ok(IpTunnel::get_from_dyn(stream))
            },
            Err(e) => Err(e)
        }
    }


    /// Create a new IPtunnel for given stream_id and interface name.
    /// Typically used on the server side of the connection.
    /// `teststream` is optionally used for testing. When set, all data from
    /// the first client to connect is also copied to UnixStream to validate
    /// the content from tunnel.
    pub fn new(
        stream_id: u64,
        ifname: &str,
        teststream: Option<tokio::net::UnixStream>,
    ) -> Result<IpTunnel, PsqError> {

        Ok(IpTunnel {
            stream_id,
            tunwriter: None,
            ifname: ifname.to_string(),
            tuntask: None,
            addresses: Vec::new(),
            teststream,
         })
    }


    pub fn addresses(&self) -> &Vec<IpAddr> {
        &self.addresses
    }


    async fn setup_tun_dev(
        &mut self,
        origconn: &Arc<Mutex<quiche::Connection>>,
        origsocket: &Arc::<UdpSocket>,
    ) -> Result<(), PsqError> {
        let conn = Arc::clone(origconn);
        let socket = Arc::clone(origsocket);

        let mut config = tun::Configuration::default();
        config
            .tun_name(&self.ifname)   // Interface name
            .mtu(1300)
            .up(); // Bring interface up

        let dev = tun::create_as_async(&config)?;
        let framed = Framed::new(dev, IpPacketCodec);
        let (writer, mut reader) = framed.split();
        self.tunwriter = Some(writer);

        let stream_id = self.stream_id;
        self.tuntask = Some(tokio::spawn(async move {
            loop {
                // TODO: proper error signaling to main program
                while let Some(Ok(packet)) = reader.next().await {
                    debug!("Interface: {}", Self::packet_output(&packet, packet.len()));
                    send_h3_dgram(&mut *conn.lock().await, stream_id, &packet)?;
                    if let Err(e) = send_quic_packets(&conn, &socket).await {
                        error!("Sending QUIC packets failed: {}", e);
                        break;
                    }
                }
            }
        }));
        Ok(())
    }


    fn check_task_error(&mut self) -> Option<PsqError> {
        if let Some(handle) = &mut self.tuntask {
            if let Some(result) = handle.now_or_never() {
                match result {
                    Ok(Ok(())) => {
                        debug!("Background task completed successfully.");
                        self.tuntask = None;
                        None
                    }
                    Ok(Err(e)) => {
                        error!("Background task returned error: {}", e);
                        self.tuntask = None;
                        Some(e)
                    }
                    Err(join_err) => {
                        error!("Background task panicked: {}", join_err);
                        self.tuntask = None;
                        Some(PsqError::Custom("Task panicked".to_string()))
                    }
                }
            } else {
                // Task still running
                None
            }
        } else {
            // No task running
            None
        }
    }


    /// Add ADDRESS_ASSIGN capsule to the given buffer. Return the size of
    /// capsule in bytes, or error.
    fn address_assign_capsule(
        &self,
        buf: &mut Vec<u8>,
        addresses: Vec<IpAddr>,
    ) -> Result<usize, PsqError> {

        let mut octets = octets::OctetsMut::with_slice(buf.as_mut_slice());

        octets.put_varint_with_len(Capsule::AddressAssign as u64, 1)?;
        octets.put_varint_with_len(0, 2)?;  // will be set in the end

        for addr in addresses {
            octets.put_varint_with_len(0, 1)?;  // Request ID == 0
            match addr {
                IpAddr::V4(v4) => {
                    octets.put_u8(4)?; // IP version = 4
                    octets.put_bytes(&v4.octets())?;
                    octets.put_u8(32)?;  // prefix
                }
                IpAddr::V6(v6) => {
                    octets.put_u8(6)?; // IP version = 6
                    octets.put_bytes(&v6.octets())?;
                    octets.put_u8(128)?;  // prefix
                }
            }
        }
        let len = octets.off();

        // Finalize capsule by setting the length.
        octets = octets::OctetsMut::with_slice(buf.as_mut_slice());
        octets.skip(1)?;
        octets.put_varint_with_len((len - 3) as u64, 2)?;

        Ok(len)
    }


    fn route_advertisement_capsule(
        &self,
        dstbuf: &mut Vec<u8>,
        offset: usize,
        srcbuf: &Vec<u8>,
    ) -> Result<usize, PsqError> {

        // TODO: this function should be reimplemented with the new zero-copy methods
        if srcbuf.len() <= 3 {
            // No addresses to advertise
            return Ok(0)
        }
        let len = srcbuf.len();
        let mut octets = octets::OctetsMut::with_slice(&mut dstbuf[offset..]);

        octets.put_varint_with_len(Capsule::RouteAdvertisement as u64, 1)?;
        octets.put_varint_with_len(len as u64, 2)?;
        octets.put_bytes(&srcbuf)?;  // TODO: should apply zero-copy bufs instead

        Ok(octets.off())
    }


    fn get_from_dyn(stream: &Box<dyn PsqStream>) -> &IpTunnel {
        stream.as_any().downcast_ref::<IpTunnel>().unwrap()
    }


    fn packet_output(buf: &[u8], bytes_read: usize) -> String {
        match buf[0] >> 4 {
            4 => {
                if buf.len() < 20 {
                    return format!("Truncated IPv4 packet");
                }
                let mut output = format!(
                    "IPv4: bytes: {}; Len: {}; Dest: {}.{}.{}.{}; Proto: {}; ",
                    bytes_read,
                    u16::from_be_bytes([buf[2], buf[3]]),
                    buf[16],buf[17],buf[18],buf[19],
                    buf[9],
                );
                if buf.len() >= 28 && (buf[9] == 6 || buf[9] == 17) {
                    output = output + &format!(
                        "Dest port: {}",
                        u16::from_be_bytes([buf[22], buf[23]])
                    );
                }
                output
            }
            6 => {
                if buf.len() < 40 {
                    return format!("Truncated IPv6 packet");
                }
                let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap());
                let mut output = format!(
                    "IPv6: bytes: {}; Payload Len: {}; Dest: {}; Next header: {}; ",
                    bytes_read,
                    u16::from_be_bytes([buf[4], buf[5]]),
                    dst,
                    buf[6],
                );
                if buf.len() >= 48 && (buf[6] == 6 || buf[6] == 17) {
                    output = output + &format!(
                        "Dest port: {}",
                        u16::from_be_bytes([buf[42], buf[43]])
                    );
                }
                output
            }
            _ => format!("Unknown IP version"),
        }
    }


    /// Process one capsule at given buffer. Both IPv4 and IPv6 are supported,
    /// although the `tun` crate does not currently support IPv6.
    /// Returns size of the capsule in bytes, or error.
    /// If there is an unknown capsule type, it is silently ignored (with log message).
    fn process_h3_capsule(&mut self, buf: &[u8]) -> Result<usize, PsqError> {
        let mut octets = octets::Octets::with_slice(buf);

        let captype = octets.get_varint()?;
        let len = octets.get_varint()?;
        debug!("Processing capsule type: {:02x}, length: {}", captype, len);

        if len + 2 > buf.len() as u64 {
            return Err(PsqError::H3Capsule("Truncated capsule received".to_string()))
        }

        let offset = match Capsule::try_from(captype) {
            Ok(Capsule::AddressAssign) => {
                self.process_address_assign(&mut octets, len)?
            },
            Ok(Capsule::RouteAdvertisement) => {
                self.process_route_advertisement(&mut octets, len)?
            },
            Err(_) => {
                warn!("Ignoring unknown capsule type: {:02x}, length: {}", captype, len);
                octets.skip(len as usize)?;
                octets.off()
            },
        };
        Ok(offset)
    }


    fn octets_to_ipv4(octets: &mut Octets) -> Result<Ipv4Addr, PsqError> {
        Ok(std::net::Ipv4Addr::new(
            octets.get_u8()?, octets.get_u8()?,
            octets.get_u8()?, octets.get_u8()?,
        ))
    }


    fn octets_to_ipv6(octets: &mut Octets) -> Result<Ipv6Addr, PsqError> {
        Ok(std::net::Ipv6Addr::new(
            octets.get_u16()?, octets.get_u16()?,
            octets.get_u16()?, octets.get_u16()?,
            octets.get_u16()?, octets.get_u16()?,
            octets.get_u16()?, octets.get_u16()?,
        ))
    }


    fn ipv4_range_to_cidr(start: Ipv4Addr, end: Ipv4Addr) -> Option<String> {
        let start = u32::from(start);
        let end = u32::from(end);

        for prefix in (0..=32).rev() {
            let mask = if prefix == 0 {
                0
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            let network = start & mask;
            let broadcast = network | !mask;

            if start >= network && end <= broadcast {
                return match Ipv4Network::new(Ipv4Addr::from(network), prefix) {
                    Ok(ip) => Some(ip.to_string()),
                    Err(_) => None,
                }
            }
        }
        None
    }


    fn ipv6_range_to_cidr(start: Ipv6Addr, end: Ipv6Addr) -> Option<String> {
        let start = u128::from(start);
        let end = u128::from(end);
    
        for prefix in (0..=128).rev() {
            let mask = if prefix == 0 {
                0
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            let network = start & mask;
            let broadcast = network | !mask;

            if start >= network && end <= broadcast {
                return match Ipv6Network::new(Ipv6Addr::from(network), prefix) {
                    Ok(ip) => Some(ip.to_string()),
                    Err(_) => None,
                }
            }
        }
        None
    }


    fn process_address_assign(
        &mut self,
        octets: &mut Octets,
        len: u64,
    ) -> Result<usize, PsqError> {

        let mut remaining = len as usize;
        while remaining >= 7 {
            let offset = octets.off();
            octets.get_varint()?;  // Request ID is ignored for now
            
            let networking = platform::get_os_networking();
            let ipver = octets.get_u8()?;
            match ipver {
                4 => {
                    let v4 = Self::octets_to_ipv4(octets)?;
                    let _prefix = octets.get_u8()?;  // no use for prefix for now
                    networking.add_address(v4.to_string().as_str(), &self.ifname)?;
                    self.addresses.push(IpAddr::V4(v4));
                    remaining -= octets.off() - offset;
                },
                6 => {
                    let v6 = Self::octets_to_ipv6(octets)?;
                    let _prefix = octets.get_u8()?;
                    networking.add_address(v6.to_string().as_str(), &self.ifname)?;
                    self.addresses.push(IpAddr::V6(v6));
                    remaining -= octets.off() - offset;
                },
                n => {
                    return Err(PsqError::H3Capsule(format!("Address assign: Invalid IP version: {}", n)))
                }
            };
        }
        if remaining > 0 {
            Err(PsqError::H3Capsule("Invalid length in Address Assign capsule".to_string()))
        } else {
            Ok(octets.off())
        }
    }


    fn process_route_advertisement(
        &mut self,
        octets: &mut Octets,
        len: u64,
    ) -> Result<usize, PsqError> {
        let mut remaining = len;
        while remaining >= 10 {
            let networking = platform::get_os_networking();

            let ipver = octets.get_u8()?;
            match ipver {
                4 => {
                    // TODO: check that end_ip >= start_ip
                    let start_ip = Self::octets_to_ipv4(octets)?;
                    let end_ip = Self::octets_to_ipv4(octets)?;
                    let _proto = octets.get_u8()?;  // For the time being protocol is ignored
                    remaining -= 10;

                    if let Some(destination) = Self::ipv4_range_to_cidr(start_ip, end_ip) {
                        networking.add_route(destination.as_str(), &self.ifname)?;
                    } else {
                        return Err(PsqError::Custom(
                            format!(
                                "Route advertisement: Invalid IPv6 address range: {} - {}",
                                start_ip.to_string(), end_ip.to_string()
                            )
                        ))
                    }
                },
                6 => {
                    // TODO: check that end_ip >= start_ip
                    let start_ip = Self::octets_to_ipv6(octets)?;
                    let end_ip = Self::octets_to_ipv6(octets)?;
                    let _proto = octets.get_u8()?;  // For the time being protocol is ignored
                    remaining -= 34;

                    if let Some(destination) = Self::ipv6_range_to_cidr(start_ip, end_ip) {
                        networking.add_route(destination.as_str(), &self.ifname)?;
                    } else {
                        return Err(PsqError::Custom(
                            format!(
                                "Route advertisement: Invalid IPv6 address range: {} - {}",
                                start_ip.to_string(), end_ip.to_string()
                            )
                        ))
                    }
                    
                },
                n => {
                    return Err(PsqError::H3Capsule(format!("Route advertisement: Invalid IP version: {}", n)))
                }
            };
        }
        Ok(octets.off())
    }
}


#[async_trait]
impl PsqStream for IpTunnel {
    async fn process_datagram(&mut self, buf: &[u8]) -> Result<(), PsqError> {
        // check if Tokio reader task is still running
        if let Some(e) = self.check_task_error() {
            error!("IP tunnel reader task failed: {}", e);
            return Err(e)
        }

        if self.tunwriter.is_some() {
            debug!("Writing to TUN: {}", Self::packet_output(&buf, buf.len()));
            let packet = BytesMut::from(&buf[..]);
            if let Err(e) = self.tunwriter.as_mut().unwrap().send(packet).await {
                error!("Send failed: {}", e);
            }
        }

        if self.teststream.is_some() && buf.len() >= 20 {
            // This is just for testing so no smart checks here.
            // We don't bother to write to teststream anything below
            // 20 bytes, because obviously it is not an IP header.
            self.teststream.as_mut().unwrap().write_all(&buf[..]).await.unwrap();
        }

        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }


    fn is_ready(&self) -> bool {
        self.tunwriter.is_some()
    }


    async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        event: quiche::h3::Event,
        buf: &mut [u8],
    ) -> Result<(), PsqError> {

        match event {
            quiche::h3::Event::Headers { list, .. } => {
                info!(
                    "got response headers {:?} on stream id {}",
                    hdrs_to_strings(&list),
                    self.stream_id
                );

                let status = get_h3_status(&list)?;
                if status != 200 {
                    return Err(PsqError::HttpResponse(status, "CONNECT request unsuccesful".to_string()))
                }
                Ok(())
            },

            quiche::h3::Event::Data => {
                let c = &mut *conn.lock().await;
                while let Ok(read) =
                    h3_conn.recv_body(c, self.stream_id, buf)
                {
                    debug!(
                        "got {} bytes of response data on stream {}",
                        read, self.stream_id
                    );

                    self.setup_tun_dev(&conn, &socket).await?;

                    // We assume that there is at least an ADDRESS_ASSIGN capsule
                    // from server. There may also be other capsules.
                    // For now, client does not choose address
                    let mut off = 0;
                    while off < read {
                        off += self.process_h3_capsule(&buf[off..read])?;
                    }
                }
                Ok(())
            },

            quiche::h3::Event::Finished => {
                info!(
                    "IpTunnel stream finished"
                );
                Err(PsqError::StreamClose("IpTunnel stream finished".into()))
            },

            quiche::h3::Event::Reset(e) => {
                error!(
                    "request was reset by peer with {}, closing...",
                    e
                );

                let c = &mut *conn.lock().await;
                c.close(true, 0x100, b"kthxbye").unwrap();
                Err(PsqError::StreamClose(format!("IpTunnel reset by peer: {}", e)))
            },

            quiche::h3::Event::PriorityUpdate => unreachable!(),

            quiche::h3::Event::GoAway => {
                info!("GOAWAY");  // TODO: process somehow
                Ok(())
            },
        }
    }


    fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl Drop for IpTunnel {
    fn drop(&mut self) {
        debug!("Dropping IpTunnel");
        if let Some(task) = &self.tuntask {
            task.abort();
        }
    }
}

unsafe impl Send for IpTunnel {}
unsafe impl Sync for IpTunnel {}


pub struct IpPacketCodec;

impl Decoder for IpPacketCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, std::io::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        let data = src.split_to(src.len());
        Ok(Some(data))
    }
}

impl Encoder<BytesMut> for IpPacketCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), std::io::Error> {
        dst.put(item);
        Ok(())
    }
}


/// Server endpoint for IP tunnel over HTTP/3 (see [RFC
/// 9484](https://datatracker.ietf.org/doc/html/rfc9484)).
/// 
/// IP endpoint can be given one or more address pools from which it assigns
/// IPv4 or IPv6 addresses to the connecting clients. It can also be assigned
/// routes that are advertised to clients.
/// 
/// Here is an example of IP endpoint with address pool and routes:
/// 
/// ```no_run
/// use pasque::{server::Config, PsqServer, IpEndpoint};
/// use std::net::SocketAddr;
/// use std::str::FromStr;
/// #[tokio::main]
/// async fn main() {
///     let config = Config::read_from_file("server.json").unwrap();
///     let mut psqserver = PsqServer::start(
///         &vec![SocketAddr::from_str("0.0.0.0:443").unwrap()],
///         &config
///     ).await.unwrap();
///
///     let mut ip_endpoint = IpEndpoint::new("tun-s");
///     ip_endpoint.add_addresspool("fd76:0212:dead::1/48".parse().unwrap()).unwrap();
///     ip_endpoint.add_route("fd76:0212:dead::/48".parse().unwrap()).unwrap();
///     ip_endpoint.add_route("::/0".parse().unwrap()).unwrap();
/// 
///     psqserver.add_endpoint("ip", Box::new(ip_endpoint)).await;
/// }
/// ```
pub struct IpEndpoint {
    /// Interface ID prefix for this interface.
    ifprefix: String,

    /// Number of point-to-point tunnels to this endpoint.
    tuncount: u32,

    /// For keeping track of available addresses to assign.
    /// There may be multiple address pools, for example separately for
    /// IPv4 and IPv6.
    addrpools: Vec<AddressPool>,

    /// Buffer for route advertisement capsule sent to new clients to this endpoint.
    /// May contain multiple IP address ranges for routes.
    route_adv: Vec<u8>,

    /// Permission label required to be present in incoming JWT token.
    permission: Option<String>,

    /// For testing support: tunneled packets are optionally written here.
    teststream: Option<tokio::net::UnixStream>,
}

impl IpEndpoint {

    /// Create a new IP tunnel endpoint.
    /// 
    /// `local_addr` is the IP address and network prefix length at the server
    /// side of the end point. When new client requests
    /// come in, they are assigned an IP address from this network prefix.
    /// 
    /// `ifprefix` is the prefix for network interface identifier for a TUN
    /// interface. For each new established tunnel server assigns a new
    /// interface based on this identifier. For example, if `ifprefix` is
    /// `tun-s0`, then the individual interfaces are `tun-s0-i0`, `tun-s0-i1`,
    /// and so on.
    pub fn new(
        ifprexix: &str,
    ) -> IpEndpoint {

        IpEndpoint {
            ifprefix: ifprexix.to_string(),
            tuncount: 0,
            addrpools: Vec::new(),
            route_adv: Vec::new(),
            permission: None,
            teststream: None,
        }
    }


    /// Advertise route via the tunnel for IP addresses indicated by the
    /// network prefix. This can be called for multiple different address
    /// ranges for the same endpoint. Works only on Linux for the time being.
    pub fn add_route(
        &mut self,
        prefix: IpNetwork,
    ) -> Result<(), PsqError> {

        let addrlen = match prefix {
            IpNetwork::V4(_) => 4,
            IpNetwork::V6(_) => 16,
        };

        let start = self.route_adv.len();
        self.route_adv.resize(start + (2 * addrlen + 2), 0);

        let mut octets = octets::OctetsMut::with_slice(self.route_adv.as_mut_slice());
        octets.skip(start)?;

        match prefix {
            IpNetwork::V4(prefix) => {
                let start = prefix.nth(0).unwrap();
                let end = prefix.nth(prefix.size()-1).unwrap();
                octets.put_u8(4)?; // IP version = 4
                octets.put_bytes(&start.octets())?;
                octets.put_bytes(&end.octets())?;
                octets.put_u8(0)?;  // all protocols allowed
            }
            IpNetwork::V6(prefix) => {
                let start = prefix.nth(0).unwrap();
                let end = prefix.nth(prefix.size()-1).unwrap();
                octets.put_u8(6)?; // IP version = 6
                octets.put_bytes(&start.octets())?;
                octets.put_bytes(&end.octets())?;
                octets.put_u8(0)?;  // all protocols allowed
            }
        };
        Ok(())
    }


    /// Add a new address pool from which addresses to clients are allocated.
    /// An endpoint can have multiple address pools, in which case client is
    /// allocated one address from each, for example separately for IPv4 and IPv6.
    pub fn add_addresspool(&mut self, ip: IpNetwork) -> Result<(), PsqError> {
        self.addrpools.push(AddressPool::new(ip)?);
        Ok(())
    }

    /// Require permission label required in incoming JWT token.
    /// If incoming request does not have JWT token, or the token does not
    /// include this permission label in its claims, the request is rejected as
    /// unauthorized.
    pub fn require_permission(
        &mut self,
        permission: &String,
    ) {
        self.permission = Some(permission.to_string());
    }


    #[cfg(all(test, feature = "tuntest"))]
    fn add_teststream(&mut self, stream: tokio::net::UnixStream) {
        self.teststream = Some(stream);
    }
}

#[async_trait]
impl Endpoint for IpEndpoint {
    async fn process_request(
        &mut self,
        request: &[quiche::h3::Header],
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        stream_id: u64,
        jwt_secret: &Vec<u8>,
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError> {

        let mut authorized = self.permission.is_none();
        for hdr in request {
            check_common_headers(hdr, "connect-ip")?;
            authorized = authorized ||
                check_authorized(hdr, self.permission.as_ref().unwrap(), jwt_secret)?;
        }

        if !authorized {
            return Err(
                PsqError::HttpResponse(401, "Authorization required".to_string())
            )
        }

        debug!("Starting IP tunnel");

        let tunif = format!("{}-i{}", self.ifprefix, self.tuncount);
        let mut iptunnel = Box::new(IpTunnel::new(
            stream_id,
            &tunif,
            self.teststream.take(),  // First client will have the teststream
        )?);

        if let Err(e) = iptunnel.setup_tun_dev(
            &conn,
            &socket,
        ).await {
            error!("Could not create TUN interface: {}", e);
            return Err(PsqError::HttpResponse(
                503,
                "Count not create TUN interface".to_string(),
            ))
        }

        // Add local addresses, and routes to remote end of tunnel
        // One for each addresspool connected to this endpoint.
        let mut addresses = Vec::<IpAddr>::new();
        let networking = get_os_networking();
        for addrpool in self.addrpools.iter_mut() {
            networking.add_address(addrpool.prefix.ip().to_string().as_str(), &tunif)?;
            let addr = addrpool.get()?;
            info!("Assigning remote address {}", addr);
            addresses.push(addr);
            networking.add_route(addr.to_string().as_str(), &tunif)?;
        }

        // TODO: This should be implemented with new Quiche zero-copy methods
        let mut body = Vec::<u8>::with_capacity(256);
        unsafe { body.set_len(256); }
        let len_aacap = iptunnel.address_assign_capsule(&mut body, addresses)?;

        let len_racap = iptunnel.route_advertisement_capsule(
            &mut body, len_aacap, &self.route_adv)?;

        body.truncate(len_aacap + len_racap);

        self.tuncount += 1;
        Ok((Some(iptunnel), body))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl fmt::Debug for IpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IpEndpoint({}", self.ifprefix)?;
        for pool in &self.addrpools {
            write!(f, " {}", pool.prefix)?;
        }
        write!(f, ")")
    }
}


/// For keeping track of available addresses.
struct AddressPool {
    prefix: IpNetwork,
    next: u128,
    used: HashSet<IpAddr>,
}

impl AddressPool {
    fn new(prefix: IpNetwork) -> Result<AddressPool, PsqError> {
        let localaddr = prefix.ip();
        let mut ap = AddressPool {
            prefix,
            next: 1,
            used: HashSet::new(),
        };
        ap.add(localaddr)?;
        Ok(ap)
    }

    fn add(&mut self, addr: IpAddr) -> Result<(), PsqError> {
        if !self.prefix.contains(addr) {
            return Err(PsqError::Custom("AddressPool: address not in range".to_string()))
        }
        match self.used.contains(&addr) {
            true => Err(PsqError::Custom("AddressPool: already in use".to_string())),
            false => {
                self.used.insert(addr);
                Ok(())
            }
        }
    }

    // TODO: Check that addresses are removed from pool when they are not used
    fn _remove(&mut self, addr: &IpAddr) {
        self.used.remove(addr);
    }

    fn nth(&self, n: usize) -> Option<IpAddr> {
        match self.prefix {
            IpNetwork::V4(v4) => v4.nth(n as u32).map(IpAddr::V4),
            IpNetwork::V6(v6) => v6.nth(n as u128).map(IpAddr::V6),
        }
    }

    fn get(&mut self) -> Result<IpAddr, PsqError> {
        let size = match self.prefix {
            IpNetwork::V4(v4) => v4.size() as u128,
            IpNetwork::V6(v6) => v6.size() as u128,
        };
        if self.used.len() as u128 >= size - 1 {
            return Err(PsqError::Custom("AddressPool: no addresses available".to_string()))
        }
        loop {
            let addr = self.nth(self.next as usize).unwrap();
            self.next += 1;
            if self.next >= size {
                self.next = 1;
            }
            if self.add(addr).is_ok() {
                return Ok(addr);
            }
        }
    }
}


#[cfg(all(test, feature = "tuntest"))]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::time::{Duration, timeout};

    use crate::{
        server::{PsqServer, config::Config},
        stream::filestream::FileStream,
        test_utils::init_logger,
    };

    use super::*;

    #[tokio::test]
    async fn test_ip_tunnel() {
        init_logger();
        let addr = "127.0.0.1:8888";
        let (tunnel, mut tester) = UnixStream::pair().unwrap();

        let server = tokio::spawn(async move {
            let config = Config::create_default();
            let mut psqserver = PsqServer::start(
                &vec![SocketAddr::from_str(addr).unwrap()],
                &config,
            ).await.unwrap();
            let mut ip_endpoint = IpEndpoint::new(
                "tun-s",
            );
            ip_endpoint.add_addresspool("10.76.0.1/24".parse().unwrap()).unwrap();
            ip_endpoint.add_route("1.1.1.0/24".parse().unwrap()).unwrap();
            ip_endpoint.add_teststream(tunnel);

            ip_endpoint.add_addresspool("fd76:0212:dead::1/48".parse().unwrap()).unwrap();
            ip_endpoint.add_route("fd76:0212:dead::/48".parse().unwrap()).unwrap();
            psqserver.add_endpoint("ip", Box::new(ip_endpoint)).await;
            loop {
                psqserver.process().await.unwrap();
            }

        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client
        let client1 = tokio::spawn(async move {

            let mut psqconn = PsqClient::connect(
                format!("https://{}/", addr).as_str(),
                true,
            ).await.unwrap();

            // Test first with GET which should not be supported on IP tunnel.
            let ret = FileStream::get(
                &mut psqconn,
                "ip",
                "testout",
            ).await;
            assert!(matches!(ret, Err(PsqError::HttpResponse(405, _))));

            // Start valid tunnel
            add_client(&mut psqconn, "tun-c1", "10.76.0.2", None).await;

            loop {
                psqconn.process().await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client2 = tokio::spawn(async move {
            let mut psqconn = PsqClient::connect(
                format!("https://{}/", addr).as_str(),
                true,
            ).await.unwrap();
            add_client(&mut psqconn, "tun-c2", "10.76.0.3", None).await;
        });

        // Try sending IPv4 datagrams through tunnel
        let result = timeout(Duration::from_millis(500), async {
            let socket = UdpSocket::bind("10.76.0.2:20000").await.unwrap();
            socket.send_to(b"Hello", "1.1.1.100:20001").await.unwrap();

            let mut buf = vec![0u8; 2000];
            loop {
                let n = tester.read(&mut buf).await.unwrap();
                debug!("packet output: {}", IpTunnel::packet_output(
                    &buf[..n],
                    n,
                ));
                if buf[9] != 128 {  // ignore non-IP packets
                    assert!(
                        u16::from_be_bytes([buf[2], buf[3]]) == 33,
                        "Invalid IPv4 packet length"
                    );
                    assert!(buf[9] == 17, "IPv4: Invalid protocol");
                    assert!(
                        u16::from_be_bytes([buf[22], buf[23]]) == 20001,
                        "IPv4: Invalid destination port"
                    );
                    assert!(
                        buf[16] == 1 &&
                        buf[17] == 1 &&
                        buf[18] == 1 &&
                        buf[19] == 100,
                        "Invalid IPv4 address",
                    );
                    break;
                }
            }
        }).await;
        assert!(result.is_ok(), "Test timed out");

        // Test sending IPv6 over tunnel
        let result = timeout(Duration::from_millis(500), async {
            let socket = UdpSocket::bind("[fd76:0212:dead::2]:20002").await.unwrap();
            socket.send_to(b"Hello", "[fd76:0212:dead::100]:20003").await.unwrap();

            let mut buf = vec![0u8; 2000];
            let n = tester.read(&mut buf).await.unwrap();
            debug!("packet output: {}", IpTunnel::packet_output(
                &buf[..n],
                n,
            ));
            assert!(
                u16::from_be_bytes([buf[4], buf[5]]) == 13,
                "Invalid IPv6 payload length"
            );
            assert!(buf[6] == 17, "IPv6: Invalid next header");
            assert!(
                buf[24] == 0xfd &&
                buf[25] == 0x76 &&
                buf[26] == 0x02 &&
                buf[27] == 0x12,
                "Invalid IPv6 address",
            );
        }).await;
        assert!(result.is_ok(), "Test timed out");

        client1.abort();
        client2.abort();
        server.abort();
    }


    async fn add_client(
        pconn: &mut PsqClient,
        ifname: &str,
        addr: &str,
        tunnel: Option<UnixStream>,
    ) {

        let iptunnel = connect_test(
            pconn,
            "ip",
            ifname,
            tunnel,
        ).await.unwrap();

        let expect_ad = *iptunnel.addresses().first().unwrap();
        assert_eq!(
            expect_ad,
            addr.parse::<std::net::IpAddr>().unwrap(),
        );
    }

    async fn connect_test<'a>(
        pconn: &'a mut PsqClient,
        urlstr: &str,
        ifname: &str,
        teststream: Option<tokio::net::UnixStream>,
    ) -> Result<&'a IpTunnel, PsqError> {

        let url = pconn.get_url().join(urlstr)?;
        let stream_id = start_connection(
            pconn,
            &url,
            "connect-ip",
        ).await?;

        // Blocks until request is replied and tunnel is set up
        let ret = pconn.add_stream(
            stream_id,
            Box::new(IpTunnel {
                stream_id,
                tunwriter: None,
                ifname: ifname.to_string(),
                tuntask: None,
                addresses: Vec::new(),
                teststream,
             })
        ).await;
        match ret {
            Ok(stream) => {
                Ok(IpTunnel::get_from_dyn(stream))
            },
            Err(e) => Err(e)
        }
    }
}
