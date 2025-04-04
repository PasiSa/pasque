use std::{
    any::Any,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{BytesMut, BufMut};
use futures::stream::{SplitSink, StreamExt};
use futures::sink::SinkExt;
use quiche::h3::NameValue;
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    sync::Mutex,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::AsyncDevice;

use crate::{
    connection::PsqConnection,
    PsqError,
    server::{Endpoint, PsqStream},
    VERSION_IDENTIFICATION,
    util::{
        build_h3_headers,
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
        let req = Self::prepare_request(&url);
        info!("sending HTTP request {:?}", req);

        let a = pconn.connection();
        let mut conn = a.lock().await;
        let h3_conn = pconn.h3_connection().as_mut().unwrap();

        let stream_id = h3_conn
            .send_request(&mut *conn, &req, true)?;

        Ok(stream_id)
    }


    pub fn new(stream_id: u64, ifname: &str) -> IpTunnel {
        IpTunnel {
            stream_id,
            tunwriter: None,
            ifname: ifname.to_string(),
            teststream: None,
         }
    }


    async fn setup_tun_dev(
        &mut self,
        stream_id: u64,
        origconn: &Arc<Mutex<quiche::Connection>>,
        origsocket: &Arc::<UdpSocket>,
        ifname: &str,
        tun_ip_local: &String,
        tun_ip_remote: &String,
    ) -> Result<(), PsqError> {
        let conn = Arc::clone(origconn);
        let socket = Arc::clone(origsocket);

        let mut config = tun::Configuration::default();
        config
            .tun_name(ifname)   // Interface name
            .address(tun_ip_local)  // Assign IP to the interface
            .destination(tun_ip_remote) // Peer address
            .netmask("255.255.255.0") // Subnet mask
            .up(); // Bring interface up
    
        let dev = tun::create_as_async(&config)?;
        let framed = Framed::new(dev, IpPacketCodec);
        let (writer, mut reader) = framed.split();
        self.tunwriter = Some(writer);

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


    /// Currently accepts just HTTP/3 Datagram and returns just (stream_id, offset).
    /// Context ID and capsule length are ignored.
    pub(crate) fn process_h3_capsule(buf: &[u8]) -> Result<(u64, usize), PsqError>{
        let mut octets = octets::Octets::with_slice(buf);

        if octets.get_u8()? != 0x00 {  // TODO: use enums instead of numbers
            // Not HTTP datagram
            return Err(PsqError::H3Capsule("Not HTTP Datagram".to_string()))
        }

        let _length = octets.get_varint()?;  // not in use at the moment

        let stream_id: u64 = octets.get_varint()? * 4;

        let _context_id = octets.get_varint()?;  // not in use at the moment

        Ok((stream_id, octets.off()))
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


    fn prepare_request(url: &url::Url) -> Vec<quiche::h3::Header> {
        let mut path = String::from(url.path());

        // TODO: move common parts to shared function
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
    
        vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            quiche::h3::Header::new(
                b":authority",
                url.host_str().unwrap().as_bytes(),
            ),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ]
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

            // Datagram capsule type (Datagram: 0x00)  TODO: Use enums
            octets.put_varint_with_len(0x00, 1)?;

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


    async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        config: &crate::config::Config,
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
                // TODO: check that response is 200 OK
                // OK response to H3 connect request
                // => bring up the TUN interface
                let local_addr = config.tun_ip_local().to_string();
                let remote_addr = config.tun_ip_remote().to_string();
                let ifname = self.ifname.clone();
                self.setup_tun_dev(
                    self.stream_id,
                    &conn,
                    &socket,
                    &ifname,
                    &local_addr,
                    &remote_addr,
                ).await?;
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

                    debug!("{}", unsafe {
                        std::str::from_utf8_unchecked(&buf[..read])
                    });
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
    local_addr: String,
    remote_addr: String,
    ifprefix: String,
    tuncount: u32,
}

impl IpEndpoint {
    pub fn new(local_addr: &str, remote_addr: &str, ifprexix: &str) -> Box<dyn Endpoint> {
        Box::new(IpEndpoint {
            local_addr: local_addr.to_string(),
            remote_addr: remote_addr.to_string(),
            ifprefix: ifprexix.to_string(),
            tuncount: 0,
        })
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
    ) -> Result<(Box<dyn PsqStream + Send + Sync + 'static>, Vec<quiche::h3::Header>, Vec<u8>), (Vec<quiche::h3::Header>, Vec<u8>)> {

        // TODO: Check that protocol and capsule protocol are correct
        for hdr in request {
            match hdr.name() {
                b":method" => {
                    if hdr.value() != b"CONNECT" {
                        return Err(build_h3_headers(
                            405, "Only CONNECT method suppored for this endpoint"
                        ))
                    }
                },
                _ => {},
            }
        }

        debug!("Starting IP tunnel");

        // TODO: parse request
        
        let (mut status, mut body) = (200, Vec::<u8>::new());

        let tunif = format!("{}-i{}", self.ifprefix, self.tuncount);
        let mut iptunnel = Box::new(IpTunnel::new(stream_id, &tunif));
        if let Err(e) = iptunnel.setup_tun_dev(
            stream_id,
            &conn,
            &socket,
            &tunif,
            &self.local_addr,
            &self.remote_addr,
        ).await {
            error!("Could not create TUN interface: {}", e);
            (status, body) = (503, Vec::from(b"Count not create TUN interface"));

        }
        
        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ),
        ];

        if status == 200 {
            self.tuncount += 1;
            Ok((iptunnel, headers, body))
        } else {
            Err((headers, body))
        }
    }
}


#[cfg(all(test, feature = "tuntest"))]
mod tests {
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::time::{Duration, timeout};

    use crate::config::Config;
    use crate::server::PsqServer;
    use crate::test_utils::init_logger;

    use super::*;

    #[test]
    fn test_ip_tunnel() {
        init_logger();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = "127.0.0.1:8888";
        rt.block_on(async {
            let (tunnel, mut tester) = UnixStream::pair().unwrap();

            let server = tokio::spawn(async move {
                let mut psqserver = PsqServer::start(addr).await.unwrap();
                psqserver.add_endpoint(
                    "ip",
                    IpEndpoint::new("10.75.0.1", "10.76.0.2", "tun-s")
                ).await;
                loop {
                    psqserver.process().await.unwrap();
                }
    
            });

            tokio::time::sleep(Duration::from_millis(100)).await;

            // Run client
            let config = match Config::read_from_file("config.json") {
                Ok(c) => c,
                Err(e) => {
                    warn!("Applying default configuration: {}", e);
                    Config::create_default()
                }
            };

            let client = tokio::spawn(async move {

                let mut psqconn = PsqConnection::connect(
                    format!("https://{}/", addr).as_str(),
                    config,
                ).await.unwrap();
                let mut _iptunnel = connect_test(
                    &mut psqconn,
                    "ip",
                    tunnel,
                ).await.unwrap();
                loop {
                    psqconn.process().await.unwrap();
                }
            });

            tokio::time::sleep(Duration::from_millis(200)).await;

            let result = timeout(Duration::from_millis(2000), async {
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

            assert!(result.is_ok(), "Test timed out");

            client.abort();
            server.abort();

        });
    }


    async fn connect_test<'a>(
        pconn: &'a mut PsqConnection,
        urlstr: &str,
        teststream: tokio::net::UnixStream,
    ) -> Result<&'a IpTunnel, PsqError> {

        let stream_id = IpTunnel::start_connection(pconn, urlstr).await?;

        // Blocks until request is replied and tunnel is set up
        let ret = pconn.add_stream(
            stream_id,
            Box::new(IpTunnel {
                stream_id,
                tunwriter: None,
                ifname: "tun-c".to_string(),
                teststream: Some(teststream),
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
