use std::{
    any::Any,
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc
};

use async_trait::async_trait;
use bytes::{BytesMut, BufMut};
use futures::stream::{SplitSink, StreamExt};
use futures::sink::SinkExt;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    sync::Mutex,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::AsyncDevice;

use super::*;
use crate::{
    connection::PsqConnection,
    PsqError,
    server::Endpoint,
    util::{
        hdrs_to_strings,
        send_quic_packets, 
        MAX_DATAGRAM_SIZE,
    },
};


/// One HTTP/3 stream established with CONNECT request.
/// Contains one proxied session/tunnel.
/// See [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484) for more information.
pub struct IpTunnel {
    stream_id: u64,
    tunwriter: Option<SplitSink<Framed<AsyncDevice, IpPacketCodec>, BytesMut>>,
    ifname: String,
    local_addr: Option<IpNetwork>,
    remote_addr: Option<IpNetwork>,

    /// For testing support: tunneled packets are optionally written here
    teststream: Option<tokio::net::UnixStream>,
}

impl IpTunnel {

    /// Sends an HTTP/3 CONNECT request to given QUIC connection, and
    /// returns created IpTunnel object in response that can be used
    /// for further tunnel/proxy operations.
    /// Blocks until response to CONNECT request is processed.
    /// 
    /// `urlstr` is URL path of the IP proxy endpoint at server. It is
    /// appended to the base URL used when establishing connection.
    pub async fn connect<'a>(
        pconn: &'a mut PsqConnection,
        urlstr: &str,
        ifname: &str,
    ) -> Result<&'a IpTunnel, PsqError> {

        let stream_id = Self::start_connection(pconn, urlstr).await?;

        // Blocks until request is replied and tunnel is set up
        let ret = pconn.add_stream(
            stream_id,
            Box::new(IpTunnel {
                stream_id,
                tunwriter: None,
                ifname: ifname.to_string(),
                local_addr: None,
                remote_addr: None,
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


    async fn start_connection<'a>(
        pconn: &'a mut PsqConnection,
        urlstr: &str,
    ) -> Result<u64, PsqError> {

        let url = pconn.get_url().join(urlstr)?;
        let req = prepare_h3_request(
            "CONNECT",
            "connect-ip",
            &url,
        );
        info!("sending HTTP request {:?}", req);

        let a = pconn.connection();
        let mut conn = a.lock().await;
        let h3_conn = pconn.h3_connection().as_mut().unwrap();

        let stream_id = h3_conn
            .send_request(&mut *conn, &req, true)?;

        Ok(stream_id)
    }


    pub fn new(
        stream_id: u64,
        ifname: &str,
        local_addr: IpNetwork,
        remote_addr: IpNetwork
    ) -> Result<IpTunnel, PsqError> {

        Ok(IpTunnel {
            stream_id,
            tunwriter: None,
            ifname: ifname.to_string(),
            local_addr: Some(local_addr),
            remote_addr: Some(remote_addr),
            teststream: None,
         })
    }


    pub fn local_addr(&self) -> &Option<IpNetwork> {
        &self.local_addr
    }


    pub fn remote_addr(&self) -> &Option<IpNetwork> {
        &self.remote_addr
    }


    async fn setup_tun_dev(
        &mut self,
        origconn: &Arc<Mutex<quiche::Connection>>,
        origsocket: &Arc::<UdpSocket>,
        ifname: &str,
    ) -> Result<(), PsqError> {
        let conn = Arc::clone(origconn);
        let socket = Arc::clone(origsocket);


        let mut config = tun::Configuration::default();
        config
            .tun_name(ifname)   // Interface name
            .address(&self.local_addr.unwrap().ip())  // Assign IP to the interface
            .destination(&self.remote_addr.unwrap().ip()) // Peer address
            .netmask("255.255.255.255") // Subnet mask
            .up(); // Bring interface up

        let dev = tun::create_as_async(&config)?;
        let framed = Framed::new(dev, IpPacketCodec);
        let (writer, mut reader) = framed.split();
        self.tunwriter = Some(writer);

        let stream_id = self.stream_id;
        tokio::spawn(async move {
            loop {
                while let Some(Ok(packet)) = reader.next().await {
                    debug!("Interface: {}", Self::packet_output(&packet, packet.len()));
                    Self::send_h3_dgram(&mut *conn.lock().await, stream_id, &packet).unwrap();
                    if let Err(e) = send_quic_packets(&conn, &socket).await {
                        error!("Sending QUIC packets failed: {}", e);
                        break;
                    }
                }
            }
        });
        Ok(())
    }


    /// Add ADDRESS_ASSIGN capsule to the given buffer. Return the size of
    /// capsule in bytes, or error.
    pub (crate) fn add_address_assign_cap(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<usize, PsqError>{

        if self.remote_addr.is_none() {
            return Err(PsqError::Custom("IP Address not defined".to_string()))
        }
        let mut octets = octets::OctetsMut::with_slice(buf.as_mut_slice());
        let ip = self.remote_addr.unwrap().ip();
        let addrlen = match ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };

        octets.put_varint_with_len(Capsule::AddressAssign as u64, 1)?;
        octets.put_varint_with_len(addrlen + 3 as u64, 1)?;

        // For the time being only single IP address is supported
        octets.put_varint_with_len(0, 1)?;  // Request ID == 0

        match ip {
            IpAddr::V4(v4) => {
                octets.put_u8(4)?; // IP version = 4
                octets.put_bytes(&v4.octets())?;
            }
            IpAddr::V6(v6) => {
                octets.put_u8(6)?; // IP version = 6
                octets.put_bytes(&v6.octets())?;
            }
        }
        octets.put_u8(self.remote_addr.unwrap().prefix())?;

        Ok(octets.off())
    }


    fn get_from_dyn(stream: &Box<dyn PsqStream>) -> &IpTunnel {
        stream.as_any().downcast_ref::<IpTunnel>().unwrap()
    }


    fn packet_output(buf: &[u8], bytes_read: usize) -> String {
        let mut output = format!(
            "bytes: {}; Len: {}; Dest: {}.{}.{}.{}; Proto: {}; ",
            bytes_read,
            u16::from_be_bytes([buf[2], buf[3]]),
            buf[16],buf[17],buf[18],buf[19],
            buf[9],
        );
        if buf[9] == 6 || buf[9] == 17 {
            output = output + &format!(
                "Dest port: {}",
                u16::from_be_bytes([buf[22], buf[23]])
            );
        }
        output
    }


    /// Sends one HTTP/3 Datagram Capsule.
    fn send_h3_dgram(
        conn: &mut quiche::Connection,
        stream_id: u64,
        buf: &[u8],
    ) -> Result<(), PsqError> {
        
        // currently we limit to stream IDs of max 16383 * 4
        //let mut data: Vec<u8> = Vec::with_capacity(6 + buf.len());
        let mut data: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
        let off = 6;

        {
            let mut octets = octets::OctetsMut::with_slice(data.as_mut_slice());

            octets.put_varint_with_len(Capsule::Datagram as u64, 1)?;

            // Datagram capsule length
            octets.put_varint_with_len(buf.len() as u64, 2)?;

            // Quarter stream ID
            // Currently supporting only 2-byte stream IDs, to be extended later
            octets.put_varint_with_len(stream_id / 4, 2)?;

            // Context ID = 0
            octets.put_varint_with_len(0, 1)?;
        }

        // Data
        let end = off + buf.len();
        data[off..end].copy_from_slice(buf);

        conn.dgram_send(&data[..end])?;
        Ok(())
    }


    /// Process one capsule at given buffer. For the time being,
    /// only ADDRESS_ASSIGN is supported. Both IPv4 and IPv6 are supported,
    /// although the `tun` crate does not currently support IPv6.
    /// Returns size of the capsule in bytes, or error.
    /// If there is an unknown capsule type, it is silently ignored (with log message).
    fn process_h3_capsule(&mut self, buf: &[u8]) -> Result<usize, PsqError> {
        let mut octets = octets::Octets::with_slice(buf);

        let captype = octets.get_u8()?;
        let len = octets.get_varint()?;
        if captype != Capsule::AddressAssign as u8 {
            warn!("Ignoring unknown capsule type: {:02x}, length: {}", captype, len);
            octets.get_bytes(len as usize)?;  // just ignore
            return Ok(octets.off());
        }
        if len + 2 > buf.len() as u64 {
            return Err(PsqError::H3Capsule("Truncated capsule received".to_string()))
        }
        octets.get_varint()?;  // Request ID is ignored for now
        
        let ipver = octets.get_u8()?;
        match ipver {
            4 => {
                if len < 3 + 4 {
                    return Err(PsqError::H3Capsule("Invalid capsule length".to_string()))
                }
                let v4 = std::net::Ipv4Addr::new(
                    octets.get_u8()?, octets.get_u8()?,
                    octets.get_u8()?, octets.get_u8()?,
                );
                let prefix = octets.get_u8()?;
                self.local_addr = match Ipv4Network::new(v4, prefix) {
                    Ok(ip) => Some(IpNetwork::V4(ip)),
                    Err(e) => {
                        return Err(PsqError::H3Capsule(format!("Invalid IPv4 address: {}", e)))
                    }
                };

                // Guess remote address for tunnel
                if let Some(IpNetwork::V4(net)) = &self.local_addr {
                    let mut octets = net.ip().octets();

                    // TODO: this is temporary, should consider prefix too
                    octets[3] = 0x01;
                    let remote_ip = std::net::Ipv4Addr::from(octets);
                    self.remote_addr = Some(IpNetwork::V4(
                        Ipv4Network::new(remote_ip, net.prefix()).map_err(|e| 
                            PsqError::H3Capsule(format!("Invalid remote IPv4 address: {}", e))
                        )?
                    ));
                }
            },
            6 => {
                if len < 3 + 16 {
                    return Err(PsqError::H3Capsule("Invalid capsule length".to_string()))
                }
                let v6 = std::net::Ipv6Addr::new(
                    octets.get_u16()?, octets.get_u16()?,
                    octets.get_u16()?, octets.get_u16()?,
                    octets.get_u16()?, octets.get_u16()?,
                    octets.get_u16()?, octets.get_u16()?,

                );
                let prefix = octets.get_u8()?;
                self.local_addr = match Ipv6Network::new(v6, prefix) {
                    Ok(ip) => Some(IpNetwork::V6(ip)),
                    Err(e) => {
                        return Err(PsqError::H3Capsule(format!("Invalid IPv6 address: {}", e)))
                    }
                };

                // Guess remote address for tunnel
                if let Some(IpNetwork::V6(net)) = &self.local_addr {
                    let mut addr = net.ip().segments();

                    // TODO: this is temporary, should consider prefix too
                    addr[7] = 0x0001;
                    let remote_ip = std::net::Ipv6Addr::new(
                        addr[0], addr[1], addr[2], addr[3],
                        addr[4], addr[5], addr[6], addr[7],
                    );
                    self.remote_addr = Some(IpNetwork::V6(
                        Ipv6Network::new(remote_ip, net.prefix()).map_err(|e| 
                            PsqError::H3Capsule(format!("Invalid remote IPv6 address: {}", e))
                        )?
                    ));
                }
            },
            n => {
                return Err(PsqError::H3Capsule(format!("Invalid IP version: {}", n)))
            }
        };

        debug!("IP address assigned: {}", self.local_addr.unwrap().ip());
        Ok(octets.off())
    }
}


#[async_trait]
impl PsqStream for IpTunnel {
    async fn process_datagram(&mut self, buf: &[u8]) -> Result<(), PsqError> {
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


    /// Called at the client when response from HTTP/3 server arrives.
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

                    // We assume that there is an ADDRESS_ASSIGN capsule from server
                    // For now, client does not choose address
                    let mut off = 0;
                    while off < read {
                        off += self.process_h3_capsule(&buf[off..read])?;
                        debug!("Processed capsule -- off: {}, read: {}", off, read);
                    }

                    if self.local_addr.is_some() {
                        let ifname = self.ifname.clone();
                        self.setup_tun_dev(
                            &conn,
                            &socket,
                            &ifname,
                        ).await?;
                    } else {
                        warn!("Could not set a tunnel -- no known IP address");
                    }
                }
            },

            quiche::h3::Event::Finished => {
                info!(
                    "IpTunnel stream finished!"
                );
            },

            quiche::h3::Event::Reset(e) => {
                error!(
                    "request was reset by peer with {}, closing...",
                    e
                );

                let c = &mut *conn.lock().await;
                c.close(true, 0x100, b"kthxbye").unwrap();
            },

            quiche::h3::Event::PriorityUpdate => unreachable!(),

            quiche::h3::Event::GoAway => {
                info!("GOAWAY");
            },
        }
        Ok(())
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

        let mut len = src.len();
        if src[0] == 0x45 && src.len() >= 20 {
            // This is likely IPv4 packet, take length from IPv4 header field.
            len = u16::from_be_bytes([src[2], src[3]]) as usize;
        }

        let data = src.split_to(len);
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


/// Endpoint for IP tunnel over HTTP/3
/// (see [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)).
pub struct IpEndpoint {
    ipnetwork: IpNetwork,
    ifprefix: String,
    tuncount: u32,
    addrpool: AddressPool,
}

impl IpEndpoint {
    pub fn new(
        local_addr: &str,
        ifprexix: &str,
    ) -> Result<Box<dyn Endpoint>, PsqError> {

        // For the time being only IPv4 is supported.
        // The current version of tun crate only supports IPv4.
        let ip = Ipv4Network::from_str(local_addr)?;
        let mut addrpool = AddressPool::new(ip);
        addrpool.add(ip.ip())?;

        Ok(Box::new(IpEndpoint {
            ipnetwork: IpNetwork::V4(ip),
            ifprefix: ifprexix.to_string(),
            tuncount: 0,
            addrpool,
        }))
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
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError> {

        check_request_headers(request, "connect-ip")?;

        debug!("Starting IP tunnel");

        let addr = IpNetwork::V4(Ipv4Network::new(self.addrpool.next()?, 32)?);

        let tunif = format!("{}-i{}", self.ifprefix, self.tuncount);
        let mut iptunnel = Box::new(IpTunnel::new(
            stream_id,
            &tunif,
            self.ipnetwork,
            addr,
        )?);

        if let Err(e) = iptunnel.setup_tun_dev(
            &conn,
            &socket,
            &tunif,
        ).await {
            error!("Could not create TUN interface: {}", e);
            return Err(PsqError::HttpResponse(
                503,
                "Count not create TUN interface".to_string(),
            ))
        }

        let mut body = Vec::<u8>::with_capacity(40);
        unsafe { body.set_len(40); }
        let off = iptunnel.add_address_assign_cap(&mut body)?;
        body.truncate(off);

        self.tuncount += 1;
        Ok((Some(iptunnel), body))
    }
}


struct AddressPool {
    prefix: Ipv4Network,
    next: u32,
    used: HashSet<Ipv4Addr>,
}

impl AddressPool {
    fn new(prefix: Ipv4Network) -> AddressPool {
        AddressPool {
            prefix,
            next: 1,
            used: HashSet::new(),
        }
    }

    fn add(&mut self, addr: Ipv4Addr) -> Result<(), PsqError> {
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
    fn _remove(&mut self, addr: &Ipv4Addr) {
        self.used.remove(addr);
    }

    fn next(&mut self) -> Result<Ipv4Addr, PsqError> {
        if self.used.len() >= self.prefix.size() as usize - 1 {
            return Err(PsqError::Custom("AddressPool: no addresses available".to_string()))
        }
        loop {
            let addr = self.prefix.nth(self.next).unwrap();
            self.next += 1;
            if self.next >= self.prefix.size() {
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
    //use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::time::Duration;

    use crate::{
        server::PsqServer,
        stream::filestream::FileStream,
        test_utils::init_logger,
    };

    use super::*;

    #[test]
    fn test_ip_tunnel() {
        init_logger();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = "127.0.0.1:8888";
        rt.block_on(async {
            let (tunnel, mut _tester) = UnixStream::pair().unwrap();

            let server = tokio::spawn(async move {
                let mut psqserver = PsqServer::start(addr).await.unwrap();
                psqserver.add_endpoint(
                    "ip",
                    IpEndpoint::new(
                        "10.76.0.1/24",
                        "tun-s",
                    ).unwrap()
                ).await;
                loop {
                    psqserver.process().await.unwrap();
                }
    
            });

            tokio::time::sleep(Duration::from_millis(100)).await;

            // Run client
            let client1 = tokio::spawn(async move {

                let mut psqconn = PsqConnection::connect(
                    format!("https://{}/", addr).as_str(),
                ).await.unwrap();

                // Test first with GET which should not be supported on IP tunnel.
                let ret = FileStream::get(
                    &mut psqconn,
                    "ip",
                    "testout",
                ).await;
                assert!(matches!(ret, Err(PsqError::HttpResponse(405, _))));

                // Start valid tunnel
                add_client(&mut psqconn, "10.76.0.2", Some(tunnel)).await;

                loop {
                    psqconn.process().await.unwrap();
                }
            });

            tokio::time::sleep(Duration::from_millis(100)).await;

            let client2 = tokio::spawn(async move {
                let mut psqconn = PsqConnection::connect(
                    format!("https://{}/", addr).as_str(),
                ).await.unwrap();
                add_client(&mut psqconn, "10.76.0.3", None).await;
            });

            // TODO: This old test does not work anymore. Leaving it as a reminder
            // to figure out some way to test TUN interface
            /*let result = timeout(Duration::from_millis(2000), async {
                let socket = UdpSocket::bind("0.0.0.0:20000").await.unwrap();
                socket.send_to(b"Hello", "10.76.0.100:20001").await.unwrap();
                socket.send_to(b"Hello", "10.76.0.100:20001").await.unwrap();

                let mut buf = vec![0u8; 2000];
                let mut count = 0;
                while count < 2 {
                    let n = tester.read(&mut buf).await.unwrap();
                    debug!("packet output: {}", IpTunnel::packet_output(
                        &buf[..n],
                        n,
                    ));
                    if count > 0 {
                        assert!(
                            u16::from_be_bytes([buf[2], buf[3]]) == 33,
                            "Invalid IP packet length"
                        );
                        assert!(buf[9] == 17, "Invalid protocol");
                        assert!(
                            u16::from_be_bytes([buf[22], buf[23]]) == 20001,
                            "Invalid destination port"
                        );
                        assert!(
                            buf[16] == 10 &&
                            buf[17] == 76 &&
                            buf[18] == 0 &&
                            buf[19] == 100,
                            "Invalid IP address",
                        );
                    }
                    count += 1;
                }
            }).await;

            assert!(result.is_ok(), "Test timed out");*/

            client1.abort();
            client2.abort();
            server.abort();

        });
    }

    async fn add_client(pconn: &mut PsqConnection, addr: &str, tunnel: Option<UnixStream>) {
        let iptunnel = connect_test(
            pconn,
            "ip",
            tunnel,
        ).await.unwrap();

        assert_eq!(
            iptunnel.local_addr().unwrap().ip(),
            addr.parse::<std::net::IpAddr>().unwrap(),
        );
    }

    async fn connect_test<'a>(
        pconn: &'a mut PsqConnection,
        urlstr: &str,
        teststream: Option<tokio::net::UnixStream>,
    ) -> Result<&'a IpTunnel, PsqError> {

        let stream_id = IpTunnel::start_connection(pconn, urlstr).await?;

        // Blocks until request is replied and tunnel is set up
        let ret = pconn.add_stream(
            stream_id,
            Box::new(IpTunnel {
                stream_id,
                tunwriter: None,
                ifname: "tun-c".to_string(),
                local_addr: None,
                remote_addr: None,
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
