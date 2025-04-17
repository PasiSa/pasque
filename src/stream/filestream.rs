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
    client::PsqClient,
    PsqError,
    server::Endpoint,
    stream::{
        prepare_h3_request,
        PsqStream,
    },
    util::hdrs_to_strings,
};


/// Stream to implement file transfer in response to GET request.
pub struct FileStream {
    stream_id: u64,
    status: u16,  // HTTP response status code
    name: String,  // local file name
    written: usize,  // bytes written to file
}

impl FileStream {

    /// Send GET request and start a stream. Completes when file is received.
    /// `urlstr` is the URL at the server. `filename` is the file created at the
    /// local file system. Returns number of bytes received or error.
    pub async fn get<'a>(
        pconn: &'a mut PsqClient,
        urlstr: &str,
        filename: &str,
    ) -> Result<usize, PsqError>{

        let url = pconn.get_url().join(urlstr)?;
        let req = prepare_h3_request("GET", "", &url);
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
                status: 0,
                name: filename.to_string(),
                written: 0,
             } )
        ).await;
        match this {
            Ok(this) => {
                let this = FileStream::get_from_dyn(this);
                if this.status == 200 {
                    Ok(this.written)
                } else {
                    Err(PsqError::HttpResponse(this.status, String::from("Error")))
                }
            },
            Err(e) => Err(e)
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
       Err(PsqError::NotSupported("Datagram received on file transfer stream".to_string()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }


    fn is_ready(&self) -> bool {
        self.status != 0
    }


    async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        _socket: &Arc<UdpSocket>,
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

                for hdr in list {
                    match hdr.name() {
                        b":status" => {
                            let s = String::from_utf8_lossy(hdr.value());
                            self.status = match s.parse::<u16>() {
                                Ok(s) => s,
                                Err(_) => {
                                    return Err(PsqError::Custom("Invalid status code in Header!".to_string()))
                                }
                            }
                        },
                        _ => (),
                    }
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

                    debug!("{}", unsafe {
                        std::str::from_utf8_unchecked(&buf[..read])
                    });

                    // TODO: very simple implementation, should do proper error handling
                    // and prepare to receive big files.
                    if self.status == 200 {
                        let mut file = std::fs::File::create(&self.name)?;
                        file.write_all(&buf[..read])?;
                        self.written = read;
                    } else {
                        return Err(PsqError::HttpResponse(
                            self.status,
                            String::from_utf8_lossy(buf).to_string()),
                        )
                    }
                }
                Ok(())
            },

            quiche::h3::Event::Finished => {
                info!(
                    "FileStream finished!"
                );
                Err(PsqError::StreamClose("FileStream finished".into()))
            },

            quiche::h3::Event::Reset(e) => {
                error!(
                    "request was reset by peer with {}, closing...",
                    e
                );

                let c = &mut *conn.lock().await;
                c.close(true, 0x100, b"kthxbye").unwrap();
                Err(PsqError::StreamClose(format!("FileStream reset by peer: {}", e)))

            },

            quiche::h3::Event::PriorityUpdate => unreachable!(),

            quiche::h3::Event::GoAway => {
                info!("GOAWAY");
                Ok(())
            },
        }
    }

    fn stream_id(&self) -> u64 {
        self.stream_id
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
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError> {

        debug!("FileStream triggered");
        let mut file_path = std::path::PathBuf::from(&self.root);
        let mut path = std::path::Path::new("");
    
        for hdr in request {
            match hdr.name() {
                b":method" => {
                    if hdr.value() != b"GET" {
                        return Err(PsqError::HttpResponse(
                            405,
                            "Method not supported for this endpoint".to_string(),
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

        let body = match std::fs::read(file_path.as_path()) {
            Ok(data) => data,

            Err(_) => return Err(PsqError::HttpResponse(404, "Not Found!".to_string())),
        };
    
        Ok((None, body))
    }
}
