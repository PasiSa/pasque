use std::time::Duration;

use tokio::{
    fs,
    net::UdpSocket,
};

use pasque::{
    client::PsqClient,
    server::{
        config::Config,
        PsqServer
    },
    stream::{
        filestream::{FileStream, Files},
        udptunnel::{UdpEndpoint, UdpTunnel}, PsqStream,
    }, test_utils::init_logger, PsqError
};


#[test]
fn test_get_request() {
    init_logger();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = "127.0.0.1:8888";
    let config = Config::create_default();
    rt.block_on(async {
        let server = tokio::spawn(async move {
            let mut psqserver = PsqServer::start(
                addr,
                &config,
            ).await.unwrap();
            psqserver.add_endpoint(
                "files", 
                Files::new(".")).await;
            loop {
                psqserver.process().await.unwrap();
            }

        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client
        let mut psqconn = PsqClient::connect(
            format!("https://{}/", addr).as_str(),
            true,
        ).await.unwrap();
        let ret = FileStream::get(
            &mut psqconn,
            "files/Cargo.toml",
            "testout",
        ).await;

        assert!(ret.is_ok());

        let srclen = fs::metadata("Cargo.toml").await.unwrap().len();
        let dstlen = fs::metadata("testout").await.unwrap().len();
        let ret = ret.unwrap();

        assert!(srclen == dstlen && srclen == ret as u64);

        let ret = FileStream::get(
            &mut psqconn,
            "files/nonexisting",
            "testout",
        ).await;
        assert!(ret.is_err());

        let ret = FileStream::get(
            &mut psqconn,
            "nonexisting",
            "testout",
        ).await;
        assert!(ret.is_err());

        std::fs::remove_file("testout").unwrap();

        server.abort();
    });
}


#[test]
fn test_udp_tunnel() {
    init_logger();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = "127.0.0.1:8889";
    rt.block_on(async {
        let server = tokio::spawn(async move {
            let config = Config::create_default();
            let mut psqserver = PsqServer::start(addr, &config).await.unwrap();
            psqserver.add_endpoint(
                "udp",
                UdpEndpoint::new().unwrap()
            ).await;
            loop {
                psqserver.process().await.unwrap();
            }

        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client
        let mut psqconn = PsqClient::connect(
            format!("https://{}/", addr).as_str(),
            true,
        ).await.unwrap();

        // Test first with GET which should not be supported on UDP tunnel.
        let ret = FileStream::get(
            &mut psqconn,
            "udp",
            "testout",
        ).await;
        assert!(matches!(ret, Err(PsqError::HttpResponse(405, _))));

        let udptunnel = UdpTunnel::connect(
            &mut psqconn,
            "udp",
            "127.0.0.1",
            9000,
            "127.0.0.1:0".parse().unwrap(),
        ).await.unwrap();
        let tunneladdr = udptunnel.sockaddr().unwrap();
        
        let client1 = tokio::spawn(async move {
            loop {
                psqconn.process().await.unwrap();
            }
        });

        // Start UDP server
        let udpsocket = UdpSocket::bind("127.0.0.1:9000").await.unwrap();

        let udpserver = tokio::spawn(async move {
            loop {
                let mut buf = [0u8; 2000];
                let (n, addr) = udpsocket.recv_from(&mut buf).await.unwrap();
                udpsocket.send_to(&buf[..n], addr).await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send UDP datagram to the client socket
        let udpclient = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let mut buf = [0u8; 2000];
        udpclient.send_to(b"Testing", tunneladdr).await.unwrap();
        let (n, _) = udpclient.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Testing");

        udpserver.abort();
        client1.abort();
        server.abort();

    });
}


#[test]
fn tunnel_closing() {
    init_logger();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = "127.0.0.1:8889";
    rt.block_on(async {
        let server = tokio::spawn(async move {
            let config = Config::create_default();
            let mut psqserver = PsqServer::start(addr, &config).await.unwrap();
            psqserver.add_endpoint(
                "udp",
                UdpEndpoint::new().unwrap()
            ).await;
            loop {
                psqserver.process().await.unwrap();
            }

        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client
        let mut psqconn = PsqClient::connect(
            format!("https://{}/", addr).as_str(),
            true,
        ).await.unwrap();

        let udptunnel = UdpTunnel::connect(
            &mut psqconn,
            "udp",
            "127.0.0.1",
            9000,
            "127.0.0.1:0".parse().unwrap(),
        ).await.unwrap();
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
        server.abort();
    });
}
