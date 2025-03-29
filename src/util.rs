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

        //debug!("{} written {} bytes", conn.trace_id(), write);
    }
    Ok(())
}


pub (crate) fn timeout_watcher(conn: Arc<Mutex<quiche::Connection>>, mut rx: watch::Receiver<Option<Duration>>) {
    tokio::spawn(async move {
        loop {
            let duration = *rx.borrow_and_update();
            // if we do not have timeout to set, sleep for 100 years.
            // Maybe someday we have proper implementation.
            let sleep_future = sleep(duration.unwrap_or(Duration::from_secs(100 * 365 * 24 * 60 * 60)));
            tokio::pin!(sleep_future);

            tokio::select! {
                _ = &mut sleep_future => {
                    debug!("timeout occurred");
                    let mut locked = conn.lock().await;
                    locked.on_timeout();
                    // TODO: Should be prepared to send packets triggered by timeout
                    break;
                }
                changed = rx.changed() => {
                    if changed.is_ok() {
                        // New duration was received, loop will recreate sleep
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


pub (crate) fn build_h3_headers(status: i32, msg: &str) -> (Vec<quiche::h3::Header>, Vec<u8>) {
    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
        quiche::h3::Header::new(
            b"content-length",
            msg.len().to_string().as_bytes(),
        ),
    ];
    (headers, msg.as_bytes().to_vec())
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
