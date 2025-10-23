use std::process::Command;

use super::*;
use crate::PsqError;

pub struct LinuxNetworking;

impl OsNetworking for LinuxNetworking {
    fn add_route(&self, destination: &str, ifname: &String) -> Result<(), PsqError> {
        debug!("Adding route: {} to iface {}", destination, ifname);

        let status = Command::new("ip")
            .args(&["route", "add", destination, "dev", ifname])
            .status()?;

        status
            .success()
            .then_some(())
            .ok_or(PsqError::Custom("Adding route failed".to_string()))
    }

    fn add_address(&self, addr: &str, ifname: &String) -> Result<(), PsqError> {
        debug!("Adding address: {} to iface {}", addr, ifname);

        let status = Command::new("ip")
            .args(["addr", "add", addr, "dev", ifname])
            .status()?;

        status
            .success()
            .then_some(())
            .ok_or(PsqError::Custom("Adding address failed".to_string()))
    }
}
