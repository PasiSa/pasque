use std::{any::Any, fmt, io::Write, sync::Arc};

use async_trait::async_trait;
use quiche::h3::NameValue;
use tokio::{net::UdpSocket, sync::Mutex};

use super::*;
use crate::{
    client::PsqClient,
    server::Endpoint,
    stream::{prepare_h3_request, PsqStream},
    PsqError,
};

/// Stream to implement file transfer in response to GET request.
pub struct FileStream {
    stream_id: u64,
    status: u16,    // HTTP response status code
    name: String,   // local file name
    written: usize, // bytes written to file
}

impl FileStream {
    /// Send GET request and start a stream. Completes when file is received.
    /// `urlstr` is the URL at the server. `filename` is the file created at the
    /// local file system. Returns number of bytes received or error.
    pub async fn get<'a>(
        pconn: &'a mut PsqClient,
        urlstr: &str,
        filename: &str,
    ) -> Result<usize, PsqError> {
        let url = pconn.get_url().join(urlstr)?;
        let req = prepare_h3_request("GET", "", &url, pconn.token());
        info!("sending HTTP request {:?}", req);

        let stream_id: u64;
        {
            let a = pconn.connection();
            let mut conn = a.lock().await;
            let h3_conn = pconn.h3_connection().as_mut().unwrap();

            stream_id = h3_conn.send_request(&mut *conn, &req, true)?;
        } // release pconn lock

        let this = pconn
            .add_stream(
                stream_id,
                Box::new(FileStream {
                    stream_id,
                    status: 0,
                    name: filename.to_string(),
                    written: 0,
                }),
            )
            .await;
        match this {
            Ok(this) => {
                let this = FileStream::get_from_dyn(this);
                if this.status == 200 {
                    Ok(this.written)
                } else {
                    Err(PsqError::HttpResponse(this.status, String::from("Error")))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn get_from_dyn(stream: &Box<dyn PsqStream>) -> &FileStream {
        stream.as_any().downcast_ref::<FileStream>().unwrap()
    }
}

#[async_trait]
impl PsqStream for FileStream {
    // Datagrams are not needed in FileStream
    async fn process_datagram(&mut self, _buf: &[u8]) -> Result<(), PsqError> {
        Err(PsqError::NotSupported(
            "Datagram received on file transfer stream".to_string(),
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_ready(&self) -> bool {
        self.status != 0
    }

    fn process_h3_headers(
        &mut self,
        _conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
        _list: &Vec<Header>,
    ) -> Result<(), PsqError> {
        Ok(())
    }

    async fn process_h3_data(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
        buf: &mut [u8],
    ) -> Result<(), PsqError> {
        let c = &mut *conn.lock().await;
        while let Ok(read) = h3_conn.recv_body(c, self.stream_id, buf) {
            debug!(
                "got {} bytes of response data on stream {}",
                read, self.stream_id
            );

            debug!("{}", unsafe { std::str::from_utf8_unchecked(&buf[..read]) });

            // TODO: very simple implementation, should do proper error handling
            // and prepare to receive big files.
            // Maintaining self.status here is silly, some further refactoring needed.
            self.status = 200;
            let mut file = std::fs::File::create(&self.name)?;
            file.write_all(&buf[..read])?;
            self.written = read;
        }
        Ok(())
    }

    fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

/// Endpoint for serving files based on incoming GET requests.
pub struct Files {
    /// Root path from which files are shared.
    root: String,

    /// Permission label required to be present in incoming JWT token.
    permission: Option<String>,
}

impl Files {
    /// Create new endpoint, serving files from directory pointed by `root`.
    pub fn new(root: &str) -> Files {
        Files {
            root: root.to_string(),
            permission: None,
        }
    }

    /// Require permission label required in incoming JWT token.
    ///
    /// If incoming request does not have JWT token, or the token does not
    /// include this permission label in its claims, the request is rejected as
    /// unauthorized.
    pub fn require_permission(&mut self, permission: &String) {
        self.permission = Some(permission.to_string());
    }
}

#[async_trait]
impl Endpoint for Files {
    async fn process_request(
        &mut self,
        request: &[quiche::h3::Header],
        _conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
        _stream_id: u64,
        jwt_secret: &Vec<u8>,
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError> {
        debug!("FileStream triggered");
        let mut file_path = std::path::PathBuf::from(&self.root);
        let mut path = std::path::Path::new("");

        let mut authorized = self.permission.is_none();
        for hdr in request {
            authorized =
                authorized || check_authorized(hdr, self.permission.as_ref().unwrap(), jwt_secret)?;

            match hdr.name() {
                b":method" => {
                    if hdr.value() != b"GET" {
                        return Err(PsqError::HttpResponse(
                            405,
                            "Method not supported for this endpoint".to_string(),
                        ));
                    }
                }
                b":path" => {
                    // UTF8 validity was already checked earlier
                    path = std::path::Path::new(std::str::from_utf8(hdr.value()).unwrap());
                }
                _ => {}
            }
        }
        if !authorized {
            return Err(PsqError::HttpResponse(
                401,
                "Authorization required".to_string(),
            ));
        }

        let mut count = 0; // hacky thing to ignore the first component of path
        for c in path.components() {
            if let std::path::Component::Normal(v) = c {
                if count > 1 {
                    file_path.push(v)
                }
            }
            count += 1;
        }

        let body = match std::fs::read(file_path.as_path()) {
            Ok(data) => data,

            Err(_) => return Err(PsqError::HttpResponse(404, "Not Found!".to_string())),
        };

        Ok((None, body))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl fmt::Debug for Files {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Files({})", self.root)
    }
}
