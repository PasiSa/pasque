use std::{
    fs::File,
    io::BufReader,
};

use serde::{Deserialize, Serialize};

use crate::PsqError;


/// Configuration read from JSON config file.
#[derive(Serialize, Deserialize)]
pub struct Config {
    cert_file: String,
    key_file: String,
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
        }
    }

    pub fn cert_file(&self) -> &String {
        &self.cert_file
    }

    pub fn key_file(&self) -> &String {
        &self.key_file
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cert_file() {
        let f = Config::read_from_file("tests/testconfig1.json");
        assert!(f.is_ok());
        let c = f.unwrap();
        assert!(c.cert_file().eq("src/bin/cert.crt"));
    }

    #[test]
    fn test_nonexisting_file() {
        let f = Config::read_from_file("XXX");
        assert!(f.is_err());
    }

    #[test]
    fn test_invalid_json() {
        let f = Config::read_from_file("tests/failconfig.txt");
        assert!(f.is_err());
    }

    #[test]
    fn test_no_fields() {
        let f = Config::read_from_file("tests/testconfig2.json");
        assert!(f.is_err());
    }

}
