use std::{
    any::Any, io::Write, sync::Arc
};

use async_trait::async_trait;
use quiche::h3::NameValue;
use tokio::{
    net::UdpSocket,
    sync::Mutex,
};

use crate::{
    connection::PsqConnection,
    PsqError,
    server::{Endpoint, PsqStream},
    util::{build_h3_headers, hdrs_to_strings},
    VERSION_IDENTIFICATION,
};


/// Stream to implement file transfer in response to GET request.
pub struct FileStream {
    stream_id: u64,
    status: String,
    name: String,
    written: usize,
}

impl FileStream {

    /// Send GET request and start a stream. Completes when file is received.
    /// `urlstr` is the URL at the server. `filename` is the file created at the
    /// local file system. Returns number of bytes received or error.
    pub async fn get<'a>(
        pconn: &'a mut PsqConnection,
        urlstr: &str,
        filename: &str,
    ) -> Result<usize, PsqError>{

        let url = pconn.get_url().join(urlstr)?;
        let req = Self::prepare_request(&url);
        info!("sending HTTP request {:?}", req);

        let stream_id: u64;
        {
            let a = pconn.connection();
            let mut conn = a.lock().await;
            let h3_conn = pconn.h3_connection().as_mut().unwrap();

            stream_id = h3_conn
                .send_request(&mut *conn, &req, true)?;
        }  // release pconn lock

        let this = pconn.add_stream(
            stream_id,
            Box::new(FileStream {
                stream_id,
                status: String::new(),
                name: filename.to_string(),
                written: 0,
             } )
        ).await;
        match this {
            Ok(this) => {
                let this = FileStream::get_from_dyn(this);
                if this.status == "200" {
                    Ok(this.written)
                } else {
                    Err(PsqError::HttpResponse(format!("Error {}", this.status)))
                }
            },
            Err(e) => Err(e)
        }
    }


    fn get_from_dyn(stream: &Box<dyn PsqStream>) -> &FileStream {
        stream.as_any().downcast_ref::<FileStream>().unwrap()
    }


    fn prepare_request(url: &url::Url) -> Vec<quiche::h3::Header> {
        let mut path = String::from(url.path());

        // TODO: move common parts to shared function
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
    
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            quiche::h3::Header::new(
                b":authority",
                url.host_str().unwrap().as_bytes(),
            ),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
        ]
    }
}

#[async_trait]
impl PsqStream for FileStream {

    // Datagrams are not needed in FileStream
    async fn process_datagram(&mut self, _buf: &[u8]) -> Result<(), PsqError> {
       Err(PsqError::NotSupported("Datagram received on file transfer stream".to_string()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }


    fn is_ready(&self) -> bool {
        self.status.len() > 0
    }


    async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
        _config: &crate::config::Config,
        event: quiche::h3::Event,
        buf: &mut [u8],
    ) -> Result<(), PsqError> {

        //let mut status: String;
        match event {
            quiche::h3::Event::Headers { list, .. } => {
                info!(
                    "got response headers {:?} on stream id {}",
                    hdrs_to_strings(&list),
                    self.stream_id
                );

                for hdr in list {
                    match hdr.name() {
                        b":status" => {
                            self.status = String::from_utf8_lossy(hdr.value()).to_string(); 
                        },
                        _ => (),
                    }
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

                    debug!("{}", unsafe {
                        std::str::from_utf8_unchecked(&buf[..read])
                    });

                    // TODO: very simple implementation, should do proper error handling
                    // and prepare to receive big files.
                    let mut file = std::fs::File::create(&self.name)?;
                    file.write_all(&buf[..read])?;
                    self.written = read;
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

/// Endpoint for serving files based on incoming GET requests.
pub struct Files {
    root: String,
}

impl Files {

    /// Create new endpoint, serving files from directory pointed by `root`.
    pub fn new(root: &str) -> Box<dyn Endpoint> {
        Box::new(Files { root: root.to_string() })
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
    ) -> Result<(Box<dyn PsqStream + Send + Sync + 'static>, Vec<quiche::h3::Header>, Vec<u8>), (Vec<quiche::h3::Header>, Vec<u8>)> {

        debug!("FileStream triggered");
        let mut file_path = std::path::PathBuf::from(&self.root);
        let mut path = std::path::Path::new("");
    
        for hdr in request {
            match hdr.name() {
                b":method" => {
                    if hdr.value() != b"GET" {
                        return Err(build_h3_headers(
                            405, "Method not supported for this endpoint"
                        ))
                    }
                },
                b":path" => {
                    // UTF8 validity was already checked earlier
                    path = std::path::Path::new(
                        std::str::from_utf8(hdr.value()).unwrap()
                    );
                },
                _ => {},
            }
        }

        let mut count = 0;  // hacky thing to ignore the first component of path
        for c in path.components() {
            if let std::path::Component::Normal(v) = c {
                if count > 1 {
                    file_path.push(v)
                }
            }
            count += 1;
        }

        let (status, body) = match std::fs::read(file_path.as_path()) {
            Ok(data) => (200, data),

            Err(_) => (404, b"Not Found!".to_vec()),
        };
    
        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ),
        ];

        // Hacky approach to use Err for succesful response, but we do not
        // need PsqStream object in this case. 
        Err((headers, body))
    }
}
