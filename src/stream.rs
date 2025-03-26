use std::sync::Arc;

use bytes::{BytesMut, BufMut};

use futures::stream::{SplitSink, StreamExt};
use futures::sink::SinkExt;

use tokio::{
    net::UdpSocket,
    sync::Mutex,
};

use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::AsyncDevice;

use crate::util::{hdrs_to_strings, send_quic_packets};


/// One HTTP/3 stream established with CONNECT request.
/// Contains one proxied session/tunnel.
pub struct PsqStream {
    stream_id: u64,
    tunwriter: Option<SplitSink<Framed<AsyncDevice, IpPacketCodec>, BytesMut>>,
}

impl PsqStream {

    /// Sends an HTTP/3 CONNECT request to given QUIC connection, and
    /// returns created PsqStream object in response that can be used
    /// for further tunnel/proxy operations.
    pub fn h3_request(
        h3_conn: &mut quiche::h3::Connection,
        conn: &mut quiche::Connection,
        url: &url::Url)
    -> PsqStream {
        let req = Self::prepare_request(&url);
        info!("sending HTTP request {:?}", req);

        let stream_id = h3_conn
            .send_request(conn, &req, true).unwrap();

        PsqStream { stream_id, tunwriter: None }

    }


    pub fn new(stream_id: u64) -> PsqStream {
        PsqStream { stream_id, tunwriter: None }
    }


    pub async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        config: &crate::config::Config,
        event: quiche::h3::Event,
        buf: &mut [u8],
    ) {
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
                self.setup_tun_dev(
                    self.stream_id,
                    &conn,
                    &socket,
                    config.tun_ip_local().to_string(),
                    config.tun_ip_remote().to_string(),
                ).await;
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
                    "response received in XX, closing..."
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
    }


    pub(crate) async fn setup_tun_dev(
        &mut self,
        stream_id: u64,
        origconn: &Arc<Mutex<quiche::Connection>>,
        origsocket: &Arc::<UdpSocket>,
        tun_ip_local: String,
        tun_ip_remote: String,
    ) {
        let conn = Arc::clone(origconn);
        let socket = Arc::clone(origsocket);

        let mut config = tun::Configuration::default();
        config
            .tun_name("tun0")   // Interface name
            .address(&tun_ip_local)  // Assign IP to the interface
            .destination(&tun_ip_remote) // Peer address
            .netmask("255.255.255.0") // Subnet mask
            .up(); // Bring interface up
    
        let dev = tun::create_as_async(&config).expect("Failed to create TUN device");
        let framed = Framed::new(dev, IpPacketCodec);
        let (writer, mut reader) = framed.split();
        self.tunwriter = Some(writer);

        tokio::spawn(async move {
            loop {
                while let Some(Ok(packet)) = reader.next().await {
                    debug!("Interface: {}", Self::packet_output(&packet, packet.len()));
                    Self::send_h3_dgram(&mut *conn.lock().await, stream_id, &packet).unwrap();
                    send_quic_packets(&conn, &socket).await;
                }
            }
        });
    }


    pub(crate) async fn process_datagram(&mut self, buf: &[u8]) {
        if self.tunwriter.is_some() {
            debug!("Writing to TUN: {}", Self::packet_output(&buf[2..], buf.len()-2));
            let packet = BytesMut::from(&buf[2..]);
            if let Err(e) = self.tunwriter.as_mut().unwrap().send(packet).await {
                error!("Send failed: {}", e);
            }
        }
    }


    fn packet_output(buf: &[u8], bytes_read: usize) -> String {
        let mut output = format!(
            "Len: {}; Dest: {}.{}.{}.{}; Proto: {}; ",
            bytes_read,
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
            quiche::h3::Header::new(b"user-agent", b"pasque"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ]
    }

    // Sends one HTTP/3 datagram
    fn send_h3_dgram(conn: &mut quiche::Connection, stream_id: u64, buf: &[u8]) -> Result<(), String> {
        // TODO: real, efficient implementation
        
        // Quarter stream ID
        let mut data = Self::make_varint(stream_id);
        
        // Context ID = 0
        data.push(0);

        // Data
        data.extend(buf);

        conn.dgram_send(&data).unwrap();
        Ok(())
    }

    fn make_varint(i: u64) -> Vec<u8> {
        // TODO: real implementation
        let ret: u8 = (i % 63) as u8;
        vec![ret]
    }
}


pub struct IpPacketCodec;

impl Decoder for IpPacketCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, std::io::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // In practice you'd parse IP headers here to know packet length
        // For now, just return the whole buffer
        let len = src.len();
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
