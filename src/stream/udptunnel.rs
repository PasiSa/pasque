use std::net::SocketAddr;

use async_trait::async_trait;
use futures::FutureExt;

use tokio::task::JoinHandle;

use super::*;
use crate::{
    client::PsqClient,
    PsqError,
    server::Endpoint,
    util::{
        hdrs_to_strings,
        send_quic_packets, 
        MAX_DATAGRAM_SIZE,
    },
};

/// UDP tunnel over HTTP/3 connection.
/// Tunnel is associated with an HTTP/3 stream established with
/// CONNECT request.
/// 
/// See [RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298) for more information.
pub struct UdpTunnel {
    stream_id: u64,
    socket: Arc<UdpSocket>,  // local socket from which data relayed to tunnel
    clientaddr: Arc<Mutex<Option<SocketAddr>>>,  // Peer address of the user of client socket
    taskhandle: Option<JoinHandle<Result<(), PsqError>>>,
}

impl UdpTunnel {

    /// Connect a new UDP tunnel using given HTTP/3 connection, as indicated
    /// with `pconn`. 
    /// 
    /// Sends an HTTP/3 CONNECT request, and if successful, returns the created
    /// UdpTunnel object in response that can be used for further tunnel/proxy
    /// operations. Blocks until response to the CONNECT request is processed.
    /// 
    /// `urlstr` is URL path of the UDP proxy endpoint at server. It is appended
    /// to the base URL used when establishing connection. `urlstr` should not
    /// contain the target address parameters, but these are given in `host` and
    /// `port`.
    /// 
    /// The established tunnel is connected to UDP socket that will be bound at
    /// `localaddr`. Wildcard addresses are allowed. You can query the actual
    /// address using the [`sockaddr`] function.
    pub async fn connect<'a>(
        pconn: &'a mut PsqClient,
        urlstr: &str,
        host: &str,
        port: u16,
        localaddr: SocketAddr,
    ) -> Result<&'a UdpTunnel, PsqError> {

        // Add host, port to URL
        let mut url = pconn.get_url().join(urlstr)?;
        url.path_segments_mut()
            .map_err(|_| PsqError::Custom(
                "Base URL cannot have a non-empty fragment".into()
            ))?
            .extend(&[host, &port.to_string()]);

        let stream_id = start_connection(
            pconn,
            &url,
            "connect-udp"
        ).await?;

        let socket = UdpSocket::bind(localaddr).await?;

        // Blocks until request is replied and tunnel is set up
        let ret = pconn.add_stream(
            stream_id,
            Box::new(UdpTunnel {
                stream_id,
                socket: Arc::new(socket),
                clientaddr: Arc::new(Mutex::new(None)),
                taskhandle: None,
            })
        ).await;
        match ret {
            Ok(stream) => {
                Ok(UdpTunnel::get_from_dyn(stream))
            },
            Err(e) => Err(e)
        }
    }


    /// Returns the address of UDP socket connected to the HTTP/3 tunnel.
    /// 
    /// All datagrams sent to this address are forwarded to the tunnel, and all
    /// datagrams coming from the tunnel can be read using this socket.
    pub fn sockaddr(&self) -> Result<std::net::SocketAddr, PsqError> {
        Ok(self.socket.local_addr()?)
    }


    fn new(
        stream_id: u64,
        socket: UdpSocket,
    ) -> Result<UdpTunnel, PsqError> {
        Ok(UdpTunnel {
            stream_id,
            socket: Arc::new(socket),
            clientaddr: Arc::new(Mutex::new(None)),
            taskhandle: None,
         })
    }


    fn get_from_dyn(stream: &Box<dyn PsqStream>) -> &UdpTunnel {
        stream.as_any().downcast_ref::<UdpTunnel>().unwrap()
    }


    fn start_socket_listener(
        &mut self,
        qconn: &Arc<Mutex<quiche::Connection>>,
        qsocket: &Arc::<UdpSocket>,
    ) {

        let qconn = Arc::clone(qconn);
        let qsocket = Arc::clone(qsocket);
        let clientaddr = Arc::clone(&self.clientaddr);
        let socket = self.socket.clone();

        let stream_id = self.stream_id;

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; MAX_DATAGRAM_SIZE];
            loop {
                let defined;
                {
                    defined = clientaddr.lock().await.is_some();
                }
                let n = match defined {
                    true => socket.recv(&mut buf).await?,
                    false => {
                        let ret = socket.recv_from(&mut buf).await?;
                        debug!("hee");
                        //let mut addrguard = clientaddr.lock().await;
                        *clientaddr.lock().await = Some(ret.1);
                        socket.connect(ret.1).await?;
                        ret.0
                    }
                };
                debug!("Sending {} bytes to HTTP/3 UDP tunnel", n);
                send_h3_dgram(&mut *qconn.lock().await, stream_id, &buf[..n])?;
                send_quic_packets(&qconn, &qsocket).await?;
            };
        });
        self.taskhandle = Some(handle);
    }


    fn check_task_error(&mut self) -> Option<PsqError> {
        if let Some(handle) = &mut self.taskhandle {
            if let Some(result) = handle.now_or_never() {
                match result {
                    Ok(Ok(())) => {
                        debug!("Background task completed successfully.");
                        self.taskhandle = None;
                        None
                    }
                    Ok(Err(e)) => {
                        error!("Background task returned error: {}", e);
                        self.taskhandle = None;
                        Some(e)
                    }
                    Err(join_err) => {
                        error!("Background task panicked: {}", join_err);
                        self.taskhandle = None;
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
}

#[async_trait]
impl PsqStream for UdpTunnel {
    async fn process_datagram(&mut self, buf: &[u8]) -> Result<(), PsqError> {

        // check if Tokio reader task is still running
        if let Some(e) = self.check_task_error() {
            error!("UDP reader task failed: {}", e);
            return Err(e)
        }

        debug!("Received {} bytes from HTTP/3 UDP tunnel", buf.len());

        if self.clientaddr.lock().await.is_none() {
            return Err(PsqError::Custom(
                "Received datagram from UDP tunnel, but no consuming socket known".into()))
        }

        self.socket.send(buf).await?;

        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }


    fn is_ready(&self) -> bool {
        self.taskhandle.is_some()
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
                self.start_socket_listener(&conn, &socket);
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


pub struct UdpEndpoint {
}

impl UdpEndpoint {
    pub fn new(
    ) -> Result<Box<dyn Endpoint>, PsqError> {

        Ok(Box::new(UdpEndpoint {
        }))
    }
}

#[async_trait]
impl Endpoint for UdpEndpoint {
    async fn process_request(
        &mut self,
        request: &[quiche::h3::Header],
        qconn: &Arc<Mutex<quiche::Connection>>,
        qsocket: &Arc<UdpSocket>,
        stream_id: u64,
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError> {

        let mut desthost = "";
        let mut destport: u16 = 0;

        for hdr in request {
            check_common_headers(hdr, "connect-udp")?;
            if hdr.name() == b":path" {
                let path = std::path::Path::new(
                    // UTF8 validity was already checked earlier
                    std::str::from_utf8(hdr.value()).unwrap()
                );

                let mut segments = path.iter();

                // Skip the first segment (like "udp")
                // TODO: implement properly
                segments.next();
                segments.next();

                let host = segments.next()
                    .ok_or_else(|| PsqError::Custom("Missing host in path".to_string()))?;
                let port = segments.next()
                    .ok_or_else(|| PsqError::Custom("Missing port in path".to_string()))?;

                desthost = host.to_str().ok_or_else(|| PsqError::Custom("Invalid UTF-8 in host".to_string()))?;
                let port_str = port.to_str().ok_or_else(|| PsqError::Custom("Invalid UTF-8 in port".to_string()))?;
                destport = port_str.parse()
                    .map_err(|_| PsqError::Custom("Invalid port number".to_string()))?;

            }
        }
        if destport == 0 {
            return Err(PsqError::Custom(
                "Could not parse destination address for the UDP tunnel".into()
            ))
        }

        debug!("Starting UDP tunnel to {}:{}", desthost, destport);

        // Open UDP socket to given address
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(format!("{}:{}", desthost, destport)).await?;

        let mut udptunnel = Box::new(UdpTunnel::new(
            stream_id,
            socket,
        )?);
        {
            *udptunnel.clientaddr.lock().await = Some(udptunnel.socket.local_addr().unwrap());
        }
        udptunnel.start_socket_listener(&qconn, &qsocket);

        let body = Vec::<u8>::new();
        Ok((Some(udptunnel), body))
    }
}
