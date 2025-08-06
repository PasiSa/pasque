use std::fs::{File, OpenOptions};
use std::io::{self};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use nix::fcntl::FcntlArg::F_SETFD;
use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag as F};
use nix::libc::{close, ioctl, setsid, TIOCSCTTY};
use nix::pty::{grantpt, posix_openpt, ptsname, unlockpt, PtyMaster};

pub(crate) fn open_handle_and_io(cmd: &mut Command) -> io::Result<(TerminalHandle, (File, File))> {
    let mut terminal_handle = TerminalHandle::open()?;

    let slave = terminal_handle.open_slave()?;

    cmd.stdin(Stdio::from(slave.try_clone()?));
    cmd.stdout(Stdio::from(slave.try_clone()?));
    cmd.stderr(Stdio::from(slave.try_clone()?));
    unsafe {
        cmd.pre_exec({
            let master = terminal_handle.0.as_raw_fd();
            move || {
                if close(master) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }

                if ioctl(0, TIOCSCTTY.into(), 1) != 0 {
                    return Err(io::Error::last_os_error());
                }

                Ok(())
            }
        })
    };

    let master_fd = terminal_handle.0.as_raw_fd();
    let io = unsafe {
        let r_fd = nix::libc::dup(master_fd);
        if r_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let w_fd = nix::libc::dup(master_fd);
        if w_fd < 0 {
            nix::libc::close(r_fd);
            return Err(io::Error::last_os_error());
        }
        (File::from_raw_fd(r_fd), File::from_raw_fd(w_fd))
    };

    Ok((terminal_handle, io))
}

pub(crate) struct TerminalHandle(PtyMaster);

impl TerminalHandle {
    fn open() -> io::Result<Self> {
        let master = posix_openpt(F::O_RDWR | F::O_NOCTTY)?;
        grantpt(&master)?;
        unlockpt(&master)?;

        let raw_flags = fcntl(master.as_raw_fd(), FcntlArg::F_GETFD)?;
        let mut flags = FdFlag::from_bits(raw_flags).unwrap();
        flags |= FdFlag::FD_CLOEXEC;

        fcntl(master.as_raw_fd(), F_SETFD(flags))?;

        Ok(TerminalHandle(master))
    }

    fn open_slave(&mut self) -> io::Result<OwnedFd> {
        let ptsname = unsafe { ptsname(&self.0) }?;

        let pts = OpenOptions::new().read(true).write(true).open(ptsname)?;

        Ok(pts.into())
    }

    pub fn _get_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
