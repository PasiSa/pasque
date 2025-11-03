//! Server side configuration settings
//!
//! Typically read from a JSON file. Includes certificate parameters and
//! configurations for different kinds of endpoints.

use std::{fs::File, io::BufReader};

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
    #[serde(default = "default_jwt_secret")]
    jwt_secret: String,
    endpoints: Vec<Endpoint>,
}

fn default_jwt_secret() -> String {
    "not-secret".to_string()
}

/// Common attributes to different endpoint types.
#[derive(Debug, Deserialize)]
pub struct Common {
    /// Path to this endpoint.
    pub path: String,

    /// Permission label required to be present in JWT token from client. If not
    /// specified, anyone can access this endpoint without authorization.
    pub permission: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Endpoint {
    IpEndpoint {
        #[serde(flatten)]
        common: Common,
        ifprefix: String,
        addresspools: Vec<String>,
        routes: Vec<String>,
    },
    UdpEndpoint {
        #[serde(flatten)]
        common: Common,
    },
    Files {
        #[serde(flatten)]
        common: Common,
        root: String,
    },
}

impl Config {
    /// Read JSON-formatted configuration from given configuration file
    pub fn read_from_file(
        filename: impl AsRef<std::path::Path>,
    ) -> core::result::Result<Config, PsqError> {
        let file = match File::open(filename) {
            Ok(f) => f,
            Err(e) => {
                return Err(PsqError::Custom(format!(
                    "Could not open config file: {}",
                    e
                )))
            }
        };
        let reader = BufReader::new(file);
        let conf: Config = match serde_json::from_reader(reader) {
            Ok(c) => c,
            Err(e) => {
                return Err(PsqError::Custom(format!(
                    "Could not parse config file: {}",
                    e
                )))
            }
        };
        Ok(conf)
    }

    /// Create a default configuration. Can be applied if configuration file cannot be read.
    pub fn create_default() -> Config {
        Config {
            cert_file: "src/bin/cert.crt".to_string(),
            key_file: "src/bin/cert.key".to_string(),
            jwt_secret: "not-secret".to_string(),
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

    /// Secret used to decode JWT tokens.
    pub fn jwt_secret(&self) -> &String {
        &self.jwt_secret
    }

    /// Apply server endpoint settings from configuration.
    /// See [server-example.json] for an example configuration
    /// with endpoints.
    ///
    /// [server-example.json]: https://github.com/PasiSa/pasque/blob/main/src/bin/server-example.json
    pub async fn set_server_endpoints(&self, server: &mut PsqServer) -> Result<(), PsqError> {
        for endpoint in &self.endpoints {
            match endpoint {
                Endpoint::IpEndpoint {
                    common,
                    ifprefix,
                    addresspools,
                    routes,
                } => {
                    debug!(
                        "Adding IpEndpoint at '{}', ifprefix: {}",
                        common.path, ifprefix
                    );
                    let mut ipendpoint = IpEndpoint::new(ifprefix);
                    for ap in addresspools {
                        debug!("Adding addresspool: {}", ap);
                        ipendpoint.add_addresspool(ap.parse()?)?;
                    }
                    for route in routes {
                        debug!("Adding route: {}", route);
                        ipendpoint.add_route(route.parse()?)?;
                    }
                    if let Some(permission) = &common.permission {
                        ipendpoint.require_permission(permission);
                    }
                    server
                        .add_endpoint(&common.path, Box::new(ipendpoint))
                        .await;
                }
                Endpoint::UdpEndpoint { common } => {
                    debug!("Adding UdpEndpoint at '{}'", common.path);
                    let mut udpendpoint = UdpEndpoint::new();
                    if let Some(permission) = &common.permission {
                        udpendpoint.require_permission(permission);
                    }
                    server
                        .add_endpoint(&common.path, Box::new(udpendpoint))
                        .await;
                }
                Endpoint::Files { common, root } => {
                    debug!("Adding Files at '{}', root: '{}'", common.path, root);
                    let mut files = Files::new(root);
                    if let Some(permission) = &common.permission {
                        files.require_permission(permission);
                    }

                    server.add_endpoint(&common.path, Box::new(files)).await;
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
