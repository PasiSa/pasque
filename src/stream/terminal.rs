use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::process::{Child, Command};

use crate::stream::terminal_unix::{open_handle_and_io, TerminalHandle};

pub struct Terminal {
    _handle: TerminalHandle,
    _process: Child, // TODO: we will need this later
    pub termin: Option<TerminalIn>,
    pub termout: Option<TerminalOut>,
}

impl Terminal {
    pub(crate) fn new(
        cmd: &mut Command,
        handle: TerminalHandle,
        (termin, termout): (File, File),
    ) -> io::Result<Self> {
        let process = cmd.spawn()?;

        Ok(Self {
            _handle: handle,
            _process: process,
            termin: Some(TerminalIn(termin)),
            termout: Some(TerminalOut(termout)),
        })
    }

    pub fn _get_fd(&self) -> RawFd {
        self._handle._get_fd()
    }

    pub fn _close(&mut self) {
        self._process.kill().unwrap();
        //self.handle.close();
    }
}

pub trait CommandExt {
    fn spawn_terminal(&mut self) -> io::Result<Terminal>;
}

impl CommandExt for Command {
    fn spawn_terminal(&mut self) -> io::Result<Terminal> {
        let (handle, (termin, termout)) = open_handle_and_io(self)?;

        Terminal::new(self, handle, (termin, termout))
    }
}

pub struct TerminalIn(File);

impl Write for TerminalIn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub struct TerminalOut(File);

impl Read for TerminalOut {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
