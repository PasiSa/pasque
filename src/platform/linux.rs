use std::process::Command;

use crate::PsqError;
use super::*;

pub struct LinuxNetworking;

impl OsNetworking for LinuxNetworking {
    fn add_route(&self, destination: &str, ifname: &String) -> Result<(), PsqError> {
        debug!("Adding Linux route: {} dev {}", destination, ifname);
        
        let status = Command::new("ip")
            .args(&["route", "add", destination, "dev", ifname])
            .status()?;

        status.success().then_some(()).ok_or(PsqError::Custom(
            "Adding route failed".to_string()
        ))
    }
}
