use std::time::Duration;


use pasque::{
    client::PsqClient,
    stream::filestream::{FileStream, Files},
    server::PsqServer,
    test_utils::init_logger,
};
use tokio::fs;


#[test]
fn test_get_request() {
    init_logger();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = "127.0.0.1:8888";
    rt.block_on(async {
        let server = tokio::spawn(async move {
            let mut psqserver = PsqServer::start(addr).await.unwrap();
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
