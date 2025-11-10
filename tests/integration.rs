use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use tokio::{fs, io::AsyncReadExt, net::UdpSocket, sync::Notify, time::timeout};

use pasque::{
    client::PsqClient,
    jwt::Jwt,
    server::{config::Config, PsqServer},
    stream::{
        filestream::{FileStream, Files},
        udptunnel::{UdpEndpoint, UdpTunnel},
        PsqStream,
    },
    test_utils::init_logger,
    PsqError, PtyClient,
};

#[tokio::test]
async fn test_get_request() {
    init_logger();
    let addr = "127.0.0.1:8888";
    let config = Config::default_without_endpoints();
    let server = tokio::spawn(async move {
        let mut psqserver = PsqServer::start(&vec![SocketAddr::from_str(addr).unwrap()], &config)
            .await
            .unwrap();
        psqserver
            .add_endpoint("files", Box::new(Files::new(".")))
            .await;
        loop {
            psqserver.process().await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client
    let mut psqconn = PsqClient::connect(format!("https://{}/", addr).as_str(), true)
        .await
        .unwrap();

    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let filestr = tmpfile.path().to_str().unwrap();
    let ret = FileStream::get(&mut psqconn, "files/Cargo.toml", filestr).await;

    assert!(ret.is_ok());

    let srclen = fs::metadata("Cargo.toml").await.unwrap().len();
    let dstlen = fs::metadata(filestr).await.unwrap().len();
    let ret = ret.unwrap();

    assert!(srclen == dstlen && srclen == ret as u64);

    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let ret = FileStream::get(
        &mut psqconn,
        "files/nonexisting",
        tmpfile.path().to_str().unwrap(),
    )
    .await;
    assert!(ret.is_err());

    let ret = FileStream::get(
        &mut psqconn,
        "nonexisting",
        tmpfile.path().to_str().unwrap(),
    )
    .await;
    assert!(ret.is_err());

    server.abort();
}

async fn run_server(addr: &str, shutdown: Arc<Notify>) {
    let config = Config::default_without_endpoints();
    let mut psqserver = PsqServer::start(&vec![SocketAddr::from_str(addr).unwrap()], &config)
        .await
        .unwrap();
    psqserver
        .add_endpoint("udp", Box::new(UdpEndpoint::new()))
        .await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                break;
            }
            result = psqserver.process() => {
                result.unwrap();
            }
        }
    }
}

async fn run_client(mut psqclient: PsqClient, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                break;
            }
            result = psqclient.process() => {
                result.unwrap();
            }
        }
    }
}

async fn run_udpserver(udpsocket: UdpSocket, shutdown: Arc<Notify>) {
    loop {
        let mut buf = [0u8; 2000];
        tokio::select! {
            _ = shutdown.notified() => {
                break;
            }
            result = udpsocket.recv_from(&mut buf) => {
                let (n, addr) = result.unwrap();
                udpsocket.send_to(&buf[..n], addr).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn test_udp_tunnel() {
    init_logger();
    let addr = "127.0.0.1:7000";
    let server_notify = Arc::new(Notify::new());
    let server = tokio::spawn(run_server(addr, server_notify.clone()));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client
    let mut psqclient = PsqClient::connect(format!("https://{}/", addr).as_str(), true)
        .await
        .unwrap();

    // Test first with GET which should not be supported on UDP tunnel.
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let ret = FileStream::get(&mut psqclient, "udp", tmpfile.path().to_str().unwrap()).await;
    assert!(matches!(ret, Err(PsqError::HttpResponse(405, _))));

    let udptunnel = UdpTunnel::connect(
        &mut psqclient,
        "udp",
        "127.0.0.1",
        9002,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let tunneladdr = udptunnel.sockaddr().unwrap();

    let client_notify = Arc::new(Notify::new());
    let client = tokio::spawn(run_client(psqclient, client_notify.clone()));

    // Start UDP server
    let udpsocket = UdpSocket::bind("127.0.0.1:9002").await.unwrap();

    let udpserver_notify = Arc::new(Notify::new());
    let udpserver = tokio::spawn(run_udpserver(udpsocket, udpserver_notify.clone()));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send UDP datagram to the client socket
    let result = timeout(Duration::from_millis(1000), async {
        let udpclient = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let mut buf = [0u8; 2000];
        udpclient.send_to(b"Testing", tunneladdr).await.unwrap();
        let (n, _) = udpclient.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Testing");
    })
    .await;
    assert!(result.is_ok(), "Test timed out");

    udpserver_notify.notify_one();
    udpserver.await.unwrap();

    client_notify.notify_one();
    client.await.unwrap();

    server_notify.notify_one();
    server.await.unwrap();
}

#[tokio::test]
async fn tunnel_closing() {
    init_logger();
    let addr = "127.0.0.1:9003";
    let server = tokio::spawn(async move {
        let config = Config::default_without_endpoints();
        let mut psqserver = PsqServer::start(&vec![SocketAddr::from_str(addr).unwrap()], &config)
            .await
            .unwrap();
        psqserver
            .add_endpoint("udp", Box::new(UdpEndpoint::new()))
            .await;
        loop {
            psqserver.process().await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client
    let mut psqconn = PsqClient::connect(format!("https://{}/", addr).as_str(), true)
        .await
        .unwrap();

    let _result = timeout(Duration::from_millis(1000), async {
        let udptunnel = UdpTunnel::connect(
            &mut psqconn,
            "udp",
            "127.0.0.1",
            9004,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let tunneladdr = udptunnel.sockaddr().unwrap();
        let stream_id = udptunnel.stream_id();

        // Send UDP datagram to the client socket
        let client1 = tokio::spawn(async move {
            let udpclient = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let mut buf = [0u8; 2000];
            udpclient.send_to(b"Testing", tunneladdr).await.unwrap();
            let (n, _) = udpclient.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Testing");
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        psqconn.remove_stream(stream_id).await;
        psqconn.process().await.unwrap();
        psqconn.remove_stream(stream_id).await;
        client1.abort();
    })
    .await;
    server.abort();
}

async fn run_server_from_config(addresses: Vec<SocketAddr>, config: Config, shutdown: Arc<Notify>) {
    let mut psqserver = PsqServer::start(&addresses, &config).await.unwrap();
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                break;
            }
            result = psqserver.process() => {
                result.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn multiple_server_addresses() {
    let addresses = vec![
        SocketAddr::from_str("127.0.0.1:7003").unwrap(),
        SocketAddr::from_str("[::1]:7003").unwrap(),
        SocketAddr::from_str("127.0.0.1:7203").unwrap(),
    ];
    let server_notify = Arc::new(Notify::new());
    let config = Config::read_from_file("tests/endpoints.json").unwrap();
    let server = tokio::spawn(run_server_from_config(
        addresses.clone(),
        config,
        server_notify.clone(),
    ));

    for addr in addresses {
        let mut psqclient = PsqClient::connect(format!("https://{}/", addr).as_str(), true)
            .await
            .unwrap();

        let _udptunnel = UdpTunnel::connect(
            &mut psqclient,
            "udp",
            "127.0.0.1",
            9002,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
    }

    server.abort();
}

#[tokio::test]
async fn authorization_success() {
    init_logger();
    let addr = "127.0.0.1:7001";
    let server_notify = Arc::new(Notify::new());
    let config = Config::read_from_file("tests/endpoints_auth.json").unwrap();
    let server = tokio::spawn(run_server_from_config(
        vec![SocketAddr::from_str(addr).unwrap()],
        config,
        server_notify.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client
    let mut psqclient = PsqClient::connect(format!("https://{}/", addr).as_str(), true)
        .await
        .unwrap();

    let secret = "very-secret".as_bytes();
    let token = Jwt::create_token(
        "user1".to_string(),
        chrono::Duration::seconds(120),
        vec!["udpauth".to_string(), "filesauth".to_string()],
        secret,
    )
    .unwrap();
    psqclient.set_token(token);

    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let ret = FileStream::get(
        &mut psqclient,
        "files/Cargo.toml",
        tmpfile.path().to_str().unwrap(),
    )
    .await;
    assert!(ret.is_ok());

    let _udptunnel = UdpTunnel::connect(
        &mut psqclient,
        "udp",
        "127.0.0.1",
        9002,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();

    server.abort();
}

#[tokio::test]
async fn authorization_failing() {
    init_logger();
    let addr = "127.0.0.1:7002";
    let server_notify = Arc::new(Notify::new());
    let config = Config::read_from_file("tests/endpoints_auth.json").unwrap();
    let server = tokio::spawn(run_server_from_config(
        vec![SocketAddr::from_str(addr).unwrap()],
        config,
        server_notify.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test client without authorization token
    let mut psqclient = PsqClient::connect(format!("https://{}/", addr).as_str(), true)
        .await
        .unwrap();

    let ret = UdpTunnel::connect(
        &mut psqclient,
        "udp",
        "127.0.0.1",
        9002,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(ret, PsqError::HttpResponse(401, _)));

    // Test client with invalid permissions
    let secret = "very-secret".as_bytes();
    let token = Jwt::create_token(
        "user1".to_string(),
        chrono::Duration::seconds(120),
        vec!["invalid".to_string()],
        secret,
    )
    .unwrap();
    psqclient.set_token(token);

    let ret = UdpTunnel::connect(
        &mut psqclient,
        "udp",
        "127.0.0.1",
        9002,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(ret, PsqError::HttpResponse(403, _)));

    server.abort();
}

#[tokio::test]
async fn pty_echo_hello() {
    let addr = "127.0.0.1:7007";
    let server_notify = Arc::new(Notify::new());
    let config = Config::read_from_file("tests/endpoints.json").unwrap();
    let server = tokio::spawn(run_server_from_config(
        vec![SocketAddr::from_str(addr).unwrap()],
        config,
        server_notify.clone(),
    ));

    let (ptyoutput, mut testreader) = tokio::io::duplex(1024);

    let url = format!("https://{}/", addr);
    let mut ptyclient = PtyClient::connect(
        url.as_str(),
        true,
        None,
        "pty",
        "sh -c \"echo Hello\"",
        Box::new(ptyoutput),
        None,
    )
    .await
    .unwrap();

    let client_task = tokio::spawn(async move {
        while ptyclient.process().await.is_ok() {
            // Just repeat until error occurs
        }
    });

    let result = timeout(Duration::from_millis(1000), async {
        let mut buf = vec![0u8; 5];
        testreader.read_exact(&mut buf).await.expect("read output");
        assert_eq!(&buf, b"Hello");
    })
    .await;
    assert!(result.is_ok(), "Test timed out");

    client_task.abort();
    server.abort();
}

#[tokio::test]
async fn pty_nonexisting_executable() {
    let addr = "127.0.0.1:7008";
    let server_notify = Arc::new(Notify::new());
    let config = Config::read_from_file("tests/endpoints.json").unwrap();
    let server = tokio::spawn(run_server_from_config(
        vec![SocketAddr::from_str(addr).unwrap()],
        config,
        server_notify.clone(),
    ));

    let (ptyoutput, mut _testreader) = tokio::io::duplex(1024);

    let url = format!("https://{}/", addr);
    let result = PtyClient::connect(
        url.as_str(),
        true,
        None,
        "pty",
        "xyzxyzxyz",
        Box::new(ptyoutput),
        None,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(result, PsqError::HttpResponse(500, _)));

    server.abort();
}
