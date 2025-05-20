#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as platform;

use crate::PsqError;


/// Platform-specific functions for networking operations.
/// 
/// If a function is not supported in the current platform, returns [PsqError::Unimplemented].
pub trait OsNetworking {
    /// Add IP route to given destination prefix.
    /// 
    /// `destination` is given as string in CIDR notation.
    fn add_route(&self, destination: &str, ifname: &String) -> Result<(), PsqError>;

    /// Assign IP address to given interface.
    fn add_address(&self, addr: &str, ifname: &String) -> Result<(), PsqError>;
}


/// Return a correct type of OsNetworking instance based on the current
/// platform.
/// 
/// For the time being only Linux is supported.
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

    fn add_address(&self, _addr: &str, _ifname: &String) -> Result<(), PsqError> {
        Err(PsqError::Unimplemented)
    }
}