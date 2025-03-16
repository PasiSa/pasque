use std::{
    fs::File,
    io::BufReader,
};

use serde::{Deserialize, Serialize};


/// Configuration read from JSON config file.
#[derive(Serialize, Deserialize)]
pub struct Config {
    tun_ip_local: String,
    tun_ip_remote: String,
}


impl Config {

    /// Read JSON-formatted configuration from given configuration file
    pub fn read_from_file(filename: &str) -> core::result::Result<Config, String> {
        let file = match File::open(filename) {
            Ok(f) => f,
            Err(e) => return Err(format!("Could not open config file: {}", e)),
        };
        let reader = BufReader::new(file);
        let conf: Config = match serde_json::from_reader(reader) {
            Ok(c) => c,
            Err(e) => return Err(format!("Could not parse config file: {}", e)),
        };
        Ok(conf)
    }


    /// Create a default configuration. Can be applied if configuration file cannot be read.
    pub fn create_default() -> Config {
        Config{
            tun_ip_local: "10.76.0.1".to_string(),
            tun_ip_remote: "10.76.0.2".to_string(),
        }
    }

    pub fn tun_ip_local(&self) -> &String {
        &self.tun_ip_local
    }

    pub fn tun_ip_remote(&self) -> &String {
        &self.tun_ip_remote
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tun_ip_local_key() {
        let f = Config::read_from_file("tests/testconfig1.json");
        assert!(f.is_ok());
        let c = f.unwrap();
        assert!(c.tun_ip_local().eq("10.76.0.1"));
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
    fn test_no_public_key() {
        let f = Config::read_from_file("tests/testconfig2.json");
        assert!(f.is_err());
    }

}
