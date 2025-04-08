use std::time::Duration;

use tokio::fs;

use pasque::{
    client::PsqClient,
    server::{PsqServer, config::Config},
    stream::filestream::{FileStream, Files},
    test_utils::init_logger
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
