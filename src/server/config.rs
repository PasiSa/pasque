//! Server side configuration settings
//! 
//! Typically read from a JSON file. Includes certificate parameters and
//! configurations for different kinds of endpoints.

use std::{
    fs::File,
    io::BufReader,
};

use serde::Deserialize;

use crate::{Files, IpEndpoint, PsqError, UdpEndpoint};

use super::PsqServer;


/// Configuration for server certificate and endpoint settings.
/// 
/// See [server-example.json] for an example on how different types of endpoints
/// are configured and what fields they have.
/// 
/// [server-example.json]: https://github.com/PasiSa/pasque/blob/main/src/bin/server-example.json
#[derive(Debug, Deserialize)]
pub struct Config {
    cert_file: String,
    key_file: String,
    endpoints: Vec<Endpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Endpoint {
    IpEndpoint {
        path: String,
        ifprefix: String,
        addresspools: Vec<String>,
        routes: Vec<String>,
    },
    UdpEndpoint {
        path: String,
    },
    Files {
        path: String,
        root: String,
    },
}

impl Config {

    /// Read JSON-formatted configuration from given configuration file
    pub fn read_from_file(filename: &str) -> core::result::Result<Config, PsqError> {
        let file = match File::open(filename) {
            Ok(f) => f,
            Err(e) => return Err(
                PsqError::Custom(format!("Could not open config file: {}", e))
            ),
        };
        let reader = BufReader::new(file);
        let conf: Config = match serde_json::from_reader(reader) {
            Ok(c) => c,
            Err(e) => return Err(
                PsqError::Custom(format!("Could not parse config file: {}", e))
            ),
        };
        Ok(conf)
    }


    /// Create a default configuration. Can be applied if configuration file cannot be read.
    pub fn create_default() -> Config {
        Config{
            cert_file: "src/bin/cert.crt".to_string(),
            key_file: "src/bin/cert.key".to_string(),
            endpoints: Vec::new(),
        }
    }

    /// File path that contains the PEM formatted TLS certificate.
    pub fn cert_file(&self) -> &String {
        &self.cert_file
    }


    /// File for private key to check the certificate.
    pub fn key_file(&self) -> &String {
        &self.key_file
    }

    /// Apply server endpoint settings from configuration.
    /// See [server-example.json] for an example configuration
    /// with endpoints.
    /// 
    /// [server-example.json]: https://github.com/PasiSa/pasque/blob/main/src/bin/server-example.json
    pub async fn set_server_endpoints(&self, server: &mut PsqServer) -> Result<(), PsqError> {
        for endpoint in &self.endpoints {
            match endpoint {
                Endpoint::IpEndpoint { path, ifprefix, addresspools, routes } => {
                    debug!("Adding IpEndpoint at '{}', ifprefix: {}", path, ifprefix);
                    let mut ipendpoint = IpEndpoint::new(ifprefix);
                    for ap in addresspools {
                        debug!("Adding addrespool: {}", ap);
                        ipendpoint.add_addresspool(ap.parse()?)?;
                    }
                    for route in routes {
                        debug!("Adding route: {}", route);
                        ipendpoint.add_route(route.parse()?)?;
                    }
                    server.add_endpoint(path, Box::new(ipendpoint)).await;
                }
                Endpoint::UdpEndpoint { path } => {
                    debug!("Adding UdpEndpoint at '{}'", path);
                    server.add_endpoint(path, UdpEndpoint::new()).await;
                }
                Endpoint::Files { path, root } => {
                    debug!("Adding Files at '{}', root: '{}'", path, root);
                    server.add_endpoint(path, Files::new(root)).await;
                }
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cert_file() {
        let f = Config::read_from_file("tests/testconfig1.json");
        assert!(f.is_ok());
        let c = f.unwrap();
        assert!(c.cert_file().eq("src/bin/cert.crt"));
    }

    #[test]
    fn nonexisting_file() {
        let f = Config::read_from_file("XXX");
        assert!(f.is_err());
    }

    #[test]
    fn invalid_json() {
        let f = Config::read_from_file("tests/failconfig.txt");
        assert!(f.is_err());
    }

    #[test]
    fn no_fields() {
        let f = Config::read_from_file("tests/testconfig2.json");
        assert!(f.is_err());
    }

}
