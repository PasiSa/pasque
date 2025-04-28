#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as platform;

use crate::PsqError;


pub trait OsNetworking {
    fn add_route(&self, destination: &str, ifname: &String) -> Result<(), PsqError>;
}


pub fn get_os_networking() -> Box<dyn OsNetworking> {
    #[cfg(target_os = "linux")]
    return Box::new(linux::LinuxNetworking);

    #[cfg(not(target_os = "linux"))]
    return Box::new(NotImplementedNetworking);
}


pub struct NotImplementedNetworking;

impl OsNetworking for NotImplementedNetworking {
    fn add_route(&self, _destination: &str, _ifname: &String) -> Result<(), PsqError> {
        Err(PsqError::Unimplemented)
    }
}