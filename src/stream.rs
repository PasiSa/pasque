use std::{
    fs::File,
    os::unix::io::{AsRawFd, FromRawFd},
    sync::Arc,
};

use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;



/// One HTTP/3 stream established with CONNECT request.
/// Contains one proxied session/tunnel.
pub struct PsqStream {
    stream_id: u64,
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

        PsqStream { stream_id }

    }


    pub async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: Arc<Mutex<quiche::Connection>>,
        config: &crate::config::Config,
        event: quiche::h3::Event,
        buf: &mut [u8],
    ) {
        match event {
            quiche::h3::Event::Headers { list, .. } => {
                info!(
                    "got response headers {:?} on stream id {}",
                    crate::hdrs_to_strings(&list),
                    self.stream_id
                );
                // TODO: check that response is 200 OK
                // OK response to H3 connect request
                // => bring up the TUN interface
                Self::setup_tun_dev(
                    self.stream_id,
                    conn,
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


    async fn setup_tun_dev(
        stream_id: u64,
        conn: Arc<Mutex<quiche::Connection>>,
        tun_ip_local: String,
        tun_ip_remote: String,
    ) {
        tokio::spawn(async move {
            let mut config = tun::Configuration::default();
            config
                .tun_name("tun0")   // Interface name
                .address(tun_ip_local)  // Assign IP to the interface
                .destination(tun_ip_remote) // Peer address
                .netmask("255.255.255.0") // Subnet mask
                .up(); // Bring interface up
        
            let tundev = tun::create(&config).expect("Failed to create TUN device");
            let fd = tundev.as_raw_fd();
            let stdfile = unsafe { File::from_raw_fd(fd) };
            let mut file = tokio::fs::File::from_std(stdfile);
            loop {
                let mut buf = [0; 65535];
                let bytes_read = file.read(&mut buf).await.unwrap();

                println!("Interface: {}", Self::packet_output(&buf, bytes_read));
                let c = &mut *conn.lock().await;
                crate::send_h3_dgram(c, stream_id, &buf[..bytes_read]).unwrap();
            }
        });
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
}
