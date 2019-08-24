use std::env;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::io;
use std::io::Write;
use std::sync::Mutex;

#[cfg(feature = "logging")]
use crate::log::warn;

/// This trait represents the ability to do something useful
/// with key material, such as logging it to a file for debugging.
///
/// Naturally, secrets passed over the interface are *extremely*
/// sensitive and can break the security of past, present and
/// future sessions.
///
/// You'll likely want some interior mutability in your
/// implementation to make this useful.
///
/// See `KeyLogFile` that implements the standard `SSLKEYLOGFILE`
/// environment variable behaviour.
pub trait KeyLog : Send + Sync {
    /// Log the given `secret`.  `client_random` is provided for
    /// session identification.  `label` describes precisely what
    /// `secret` means:
    ///
    /// - `CLIENT_RANDOM`: `secret` is the master secret for a TLSv1.2 session.
    /// - `CLIENT_EARLY_TRAFFIC_SECRET`: `secret` encrypts early data
    ///   transmitted by a client
    /// - `SERVER_HANDSHAKE_TRAFFIC_SECRET`: `secret` encrypts
    ///   handshake messages from the server during a TLSv1.3 handshake.
    /// - `CLIENT_HANDSHAKE_TRAFFIC_SECRET`: `secret` encrypts
    ///   handshake messages from the client during a TLSv1.3 handshake.
    /// - `SERVER_TRAFFIC_SECRET_0`: `secret` encrypts post-handshake data
    ///   from the server in a TLSv1.3 session.
    /// - `CLIENT_TRAFFIC_SECRET_0`: `secret` encrypts post-handshake data
    ///   from the client in a TLSv1.3 session.
    /// - `EXPORTER_SECRET`: `secret` is the post-handshake exporter secret
    ///   in a TLSv1.3 session.
    ///
    /// These strings are selected to match the NSS key log format:
    /// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);

    /// Indicates whether the secret with label `label` will be logged.
    ///
    /// If `will_log` returns true then `log` will be called with the secret.
    /// Otherwise, `log` will not be called for the secret. This is a
    /// performance optimization.
    fn will_log(&self, _label: &str) -> bool { true }
}

/// KeyLog that does exactly nothing.
pub struct NoKeyLog;

impl KeyLog for NoKeyLog {
    fn log(&self, _: &str, _: &[u8], _: &[u8]) {}
    #[inline]
    fn will_log(&self, _label: &str) -> bool { false }
}

// Internal mutable state for KeyLogFile
struct KeyLogFileInner {
    file: Option<File>,
    buf: Vec<u8>,
}

impl KeyLogFileInner {
    fn new() -> Self {
        let var = env::var("SSLKEYLOGFILE");
        let path = match var {
            Ok(ref s) => Path::new(s),
            Err(env::VarError::NotUnicode(ref s)) => Path::new(s),
            Err(env::VarError::NotPresent) => {
                return KeyLogFileInner {
                    file: None,
                    buf: Vec::new(),
                };
            }
        };

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        let file = match OpenOptions::new()
            .append(true)
            .create(true)
            .open(path) {
            Ok(f) => Some(f),
            Err(e) => {
                warn!("unable to create key log file '{:?}': {}", path, e);
                None
            }
        };

        KeyLogFileInner {
            file,
            buf: Vec::new(),
        }
    }

    fn try_write(&mut self, label: &str, client_random: &[u8], secret: &[u8]) -> io::Result<()> {
        let mut file = match self.file {
            None => { return Ok(()); }
            Some(ref f) => f,
        };

        self.buf.truncate(0);
        write!(self.buf, "{} ", label)?;
        for b in client_random.iter() {
            write!(self.buf, "{:02x}", b)?;
        }
        write!(self.buf, " ")?;
        for b in secret.iter() {
            write!(self.buf, "{:02x}", b)?;
        }
        writeln!(self.buf)?;
        file.write_all(&self.buf)
    }
}

/// `KeyLog` implementation that opens a file whose name is
/// given by the `SSLKEYLOGFILE` environment variable, and writes
/// keys into it.
///
/// If `SSLKEYLOGFILE` is not set, this does nothing.
///
/// If such a file cannot be opened, or cannot be written then
/// this does nothing but logs errors at warning-level.
pub struct KeyLogFile(Mutex<KeyLogFileInner>);

impl KeyLogFile {
    /// Makes a new `KeyLogFile`.  The environment variable is
    /// inspected and the named file is opened during this call.
    pub fn new() -> Self {
        KeyLogFile(Mutex::new(KeyLogFileInner::new()))
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        match self.0.lock()
            .unwrap()
            .try_write(label, client_random, secret) {
            Ok(()) => {},
            Err(e) => {
                warn!("error writing to key log file: {}", e);
            }
        }
    }
}

