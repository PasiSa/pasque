use std::{
    fmt,
    io::{Read, Write},
    process::Command,
};

use async_trait::async_trait;
use shlex::Shlex;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use super::*;
use crate::{
    server::{clientsession::ClientSession, Endpoint},
    stream::terminal::{CommandExt, Terminal},
    util::send_quic_packets,
    PsqError,
};

pub struct PtyClient {
    pclient: PsqClient,
}

impl PtyClient {
    pub async fn connect<'a>(
        urlstr: &str,
        ignore_cert: bool,
        token: Option<&String>,
        urlpath: &str,
        command: &str,
    ) -> Result<PtyClient, PsqError> {
        let mut pclient = PsqClient::connect(urlstr, ignore_cert).await?;

        if let Some(t) = token {
            pclient.set_token(t.clone());
        }
        let mut url = pclient.get_url().join(urlpath)?;
        url.query_pairs_mut().append_pair("cmd", command);

        let stream_id = start_connection(&mut pclient, &url, "connect-pty").await?;

        let mut stream = Box::new(PtyStream {
            stream_id,
            taskhandle: None,
            terminal: None,
            ready: false,
            client: true,
        });

        stream.start_client_reader(
            &pclient.connection(),
            &pclient.socket(),
            &pclient.h3_connection().as_ref().unwrap(),
        );

        // Blocks until request is replied and tunnel is set up
        let ret = pclient.add_stream(stream_id, stream).await;

        match ret {
            Ok(_) => Ok(PtyClient { pclient }),
            Err(e) => Err(e),
        }
    }

    pub async fn process(&mut self) -> Result<(), PsqError> {
        self.pclient.process().await
    }
}

pub struct PtyStream {
    stream_id: u64,
    taskhandle: Option<JoinHandle<Result<(), PsqError>>>,
    terminal: Option<Terminal>, // Only set at the server end
    ready: bool,
    client: bool, // true if client, false if server
}

impl PtyStream {
    fn new(stream_id: u64, client: bool, command: &str) -> Result<PtyStream, PsqError> {
        let parts = Shlex::new(command);
        let mut argvec: Vec<String> = parts.collect();

        if argvec.is_empty() {
            return Err(PsqError::Custom("empty command".into()));
        }

        let program = argvec.remove(0);
        let mut cmd = Command::new(program);
        cmd.args(&argvec);

        let terminal = cmd.spawn_terminal()?;
        Ok(PtyStream {
            stream_id,
            taskhandle: None,
            terminal: Some(terminal),
            ready: false,
            client,
        })
    }

    fn start_client_reader(
        &mut self,
        qconn: &Arc<Mutex<quiche::Connection>>,
        qsocket: &Arc<UdpSocket>,
        h3_connection: &Arc<Mutex<quiche::h3::Connection>>,
    ) {
        let qconn = Arc::clone(qconn);
        let qsocket = Arc::clone(qsocket);
        let h3_conn = Arc::clone(h3_connection);

        let stream_id = self.stream_id;

        self.taskhandle = Some(tokio::spawn(async move {
            let mut buf = [0u8; 10000];
            let mut stdin = io::stdin();
            loop {
                let n = stdin.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                {
                    let conn = &mut *qconn.lock().await;
                    // TODO: Send H3 DATA frame instead
                    let h3 = &mut *h3_conn.lock().await;
                    let _written = match h3.send_body(conn, stream_id, &buf[..n], false) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::Done) => 0,

                        Err(e) => {
                            error!("{} stream send failed {:?}", conn.trace_id(), e);
                            return Err(PsqError::Http3(e));
                        }
                    };
                }

                send_quic_packets(&qconn, &qsocket).await?;
            }
        }));
    }

    /// This is run at the server end.
    fn start_terminal_reader(&mut self, session: &ClientSession) {
        let stream_id = self.stream_id;
        let mut terminal_reader = match self.terminal.as_mut().unwrap().termout.take() {
            Some(reader) => reader,
            None => {
                warn!("No terminal reader found");
                return;
            }
        };

        let qconn = Arc::clone(session.connection());
        let h3_conn = Arc::clone(&session.h3_connection().as_ref().unwrap());
        let qsocket = Arc::clone(session.socket());

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];

            loop {
                let n = match terminal_reader.read(&mut buf) {
                    Ok(0) => {
                        debug!("Terminal closed, ending listener task");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        error!("Failed to read from terminal: {:?}", e);
                        break;
                    }
                };

                {
                    let conn = &mut *qconn.lock().await;
                    // TODO: Send H3 DATA frame instead
                    let h3 = &mut *h3_conn.lock().await;
                    let _written = match h3.send_body(conn, stream_id, &buf[..n], false) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::Done) => 0,

                        Err(e) => {
                            error!("{} stream send failed {:?}", conn.trace_id(), e);
                            return Err(PsqError::Http3(e));
                        }
                    };
                }

                send_quic_packets(&qconn, &qsocket).await?;
            }

            Ok(())
        });

        self.taskhandle = Some(handle);
    }
}

#[async_trait]
impl PsqStream for PtyStream {
    async fn process_datagram(&mut self, _buf: &[u8]) -> Result<(), PsqError> {
        Err(PsqError::Unimplemented)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_ready(&self) -> bool {
        self.ready
    }

    fn process_h3_headers(
        &mut self,
        _conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
        _list: &Vec<Header>,
    ) -> Result<(), PsqError> {
        // TODO: check that response is OK
        self.ready = true;
        Ok(())
    }

    async fn process_h3_response(
        &mut self,
        h3_conn: &Arc<Mutex<quiche::h3::Connection>>,
        conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
        buf: &mut [u8],
    ) -> Result<(), PsqError> {
        let c = &mut *conn.lock().await;
        while let Ok(read) = h3_conn.lock().await.recv_body(c, self.stream_id, buf) {
            debug!(
                "got {} bytes of response data on stream {}",
                read, self.stream_id
            );
        }
        Ok(())
    }

    async fn process_data(&mut self, buf: &[u8]) -> Result<(), PsqError> {
        if self.client {
            let mut stdout = io::stdout();
            if let Err(e) = stdout.write_all(&buf).await {
                error!("stdout write failed: {}", e);
                return Err(PsqError::Io(e));
            }
        } else {
            if let Some(termin) = self.terminal.as_mut().unwrap().termin.as_mut() {
                let _n = termin.write(buf)?;
            } else {
                warn!("Could not write to terminal, because one is not defined");
                // Error?
            }
        }
        Ok(())
    }

    fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

pub struct PtyEndpoint {
    /// Permission label required to be present in incoming JWT token.
    permission: Option<String>,
}

impl PtyEndpoint {
    pub fn new() -> PtyEndpoint {
        PtyEndpoint { permission: None }
    }

    /// Permission label required in incoming JWT token.
    ///
    /// If incoming request does not have JWT token, or the token does not
    /// include this permission label in its claims, the request is rejected as
    /// unauthorized.
    pub fn require_permission(&mut self, permission: &String) {
        self.permission = Some(permission.to_string());
    }
}

#[async_trait]
impl Endpoint for PtyEndpoint {
    async fn process_request(
        &mut self,
        request: &[quiche::h3::Header],
        session: &ClientSession,
        stream_id: u64,
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError> {
        let mut authorized = self.permission.is_none();
        for hdr in request {
            check_common_headers(hdr, "connect-pty")?;
            authorized = authorized
                || check_authorized(
                    hdr,
                    self.permission.as_ref().unwrap(),
                    session.jwt_secret(), /*jwt_secret*/
                )?;
        }

        if !authorized {
            return Err(PsqError::HttpResponse(
                401,
                "Authorization required".to_string(),
            ));
        }

        // Extract the `cmd` query parameter from the :path header (default: "bash")
        let command = session
            .get_query_params(stream_id)
            .as_ref()
            .and_then(|map| map.get("cmd"))
            .map(|s| s.as_str())
            .unwrap_or("bash");

        let mut ptystream = Box::new(PtyStream::new(stream_id, false, &command)?);

        ptystream.start_terminal_reader(session);

        let body = Vec::<u8>::new();
        Ok((Some(ptystream), body))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl fmt::Debug for PtyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PtyEndpoint()")
    }
}
