use std::sync::Arc;

use quiche::h3::NameValue;

use tokio::{
    net::UdpSocket,
    sync::{watch, Mutex},
    time::{sleep, Duration},
};

use crate::{PsqError, VERSION_IDENTIFICATION};

pub const MAX_DATAGRAM_SIZE: usize = 1350;


pub (crate) async fn send_quic_packets(
    conn: &Arc<Mutex<quiche::Connection>>,
    socket: &Arc<UdpSocket>,
) -> Result<(), PsqError> {

    let mut out = [0; MAX_DATAGRAM_SIZE];
    loop {
        let mut conn = conn.lock().await;
        let (write, send_info) = match conn.send(&mut out) {
            Ok(v) => v,

            Err(quiche::Error::Done) => {
                break;
            },

            Err(e) => {
                error!("{} send failed: {:?}", conn.trace_id(), e);

                conn.close(false, 0x1, b"fail").ok();
                return Err(PsqError::Quiche(e))
            },
        };

        if let Err(e) = socket.send_to(&out[..write], send_info.to).await {
            error!("UDP send() failed: {:?}", e);
            return Err(PsqError::Io(e))
        }
    }
    Ok(())
}


pub (crate) fn timeout_watcher(
    conn: Arc<Mutex<quiche::Connection>>,
    socket: Arc<UdpSocket>,
    mut rx: watch::Receiver<Option<Duration>>) {

    tokio::spawn(async move {
        loop {
            let conn_guard = conn.lock().await;
            let duration = conn_guard.timeout();
            drop(conn_guard);

            let sleep_future = sleep(duration.unwrap_or(Duration::from_secs(100 * 365 * 24 * 60 * 60)));
            tokio::pin!(sleep_future);

            tokio::select! {
                _ = &mut sleep_future => {
                    debug!("timeout occurred");
                    conn.lock().await.on_timeout();
                    if let Err(e) = send_quic_packets(&conn, &socket).await {
                        error!("Timeout occurred, but sending QUIC packets failed: {}", e);
                    }
                    continue;
                }
                changed = rx.changed() => {
                    if changed.is_ok() {
                        debug!("[Watcher] Timeout changed to {:?}", *rx.borrow());
                        continue;
                    } else {
                        break; // channel closed
                    }
                }
            }
        }
    });
}


pub (crate) fn build_h3_headers(status: u16, body: &Vec<u8>) -> Vec<quiche::h3::Header> {
    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
        // lazily include capsule-protocol in all responses (also GET)
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ),
    ];
    headers
}


pub (crate) fn build_h3_response(status: u16, msg: &str) -> (Vec<quiche::h3::Header>, Vec<u8>) {
    let body = msg.as_bytes().to_vec();
    (build_h3_headers(status, &body), body)
}


pub (crate) fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
