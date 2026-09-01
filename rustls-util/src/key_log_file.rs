use core::fmt::{Debug, Formatter};
use std::env::var_os;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

use rustls::KeyLog;
#[cfg(feature = "tracing")]
use tracing::warn;

// Internal mutable state for KeyLogFile
struct KeyLogFileInner {
    file: Option<File>,
    buf: Vec<u8>,
}

impl KeyLogFileInner {
    fn new(var: Option<OsString>) -> Self {
        let Some(path) = &var else {
            return Self {
                file: None,
                buf: Vec::new(),
            };
        };

        let mut options = OpenOptions::new();
        options.append(true).create(true);
        // Key material is extremely sensitive. On Unix, create with owner-only
        // access so a default umask does not leave the file world-readable.
        #[cfg(unix)]
        options.mode(0o600);

        #[cfg_attr(not(feature = "tracing"), expect(clippy::manual_ok_err))]
        let file = match options.open(path) {
            Ok(f) => Some(f),
            #[cfg_attr(not(feature = "tracing"), expect(unused_variables))]
            Err(e) => {
                #[cfg(feature = "tracing")]
                warn!("unable to create key log file {path:?}: {e}");
                None
            }
        };

        Self {
            file,
            buf: Vec::new(),
        }
    }

    fn try_write(&mut self, label: &str, client_random: &[u8], secret: &[u8]) -> io::Result<()> {
        let Some(file) = &mut self.file else {
            return Ok(());
        };

        self.buf.clear();
        write!(self.buf, "{label} ")?;
        for b in client_random.iter() {
            write!(self.buf, "{b:02x}")?;
        }
        write!(self.buf, " ")?;
        for b in secret.iter() {
            write!(self.buf, "{b:02x}")?;
        }
        writeln!(self.buf)?;
        file.write_all(&self.buf)
    }
}

impl Debug for KeyLogFileInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyLogFileInner")
            // Note: we omit self.buf deliberately as it may contain key data.
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

/// [`KeyLog`] implementation that opens a file whose name is
/// given by the `SSLKEYLOGFILE` environment variable, and writes
/// keys into it.
///
/// If `SSLKEYLOGFILE` is not set, this does nothing.
///
/// If such a file cannot be opened, or cannot be written then
/// this does nothing but logs errors at warning-level.
///
/// # Security
///
/// Key material is extremely sensitive. Prefer not enabling `KeyLog`
/// outside of local debugging. On Unix, files created by this type use
/// owner-only permissions (`0o600`).
///
/// This type reads `SSLKEYLOGFILE` from the process environment with a
/// normal environment lookup. In a setuid/setgid (or otherwise elevated)
/// process, that variable may have been inherited from an untrusted parent
/// and could point at an attacker-chosen path. Applications that raise
/// privileges should clear sensitive environment variables, avoid compiling
/// key-log support into production builds, or supply their own [`KeyLog`]
/// implementation.
///
/// This util is intentionally small. It does not attempt a full
/// `secure_getenv`-style environment filter.
pub struct KeyLogFile(Mutex<KeyLogFileInner>);

impl KeyLogFile {
    /// Makes a new `KeyLogFile`.  The environment variable is
    /// inspected and the named file is opened during this call.
    pub fn new() -> Self {
        let var = var_os("SSLKEYLOGFILE");
        Self(Mutex::new(KeyLogFileInner::new(var)))
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match self
            .0
            .lock()
            .unwrap()
            .try_write(label, client_random, secret)
        {
            Ok(()) => {}
            #[cfg_attr(not(feature = "tracing"), expect(unused_variables))]
            Err(e) => {
                #[cfg(feature = "tracing")]
                warn!("error writing to key log file: {e}");
            }
        }
    }
}

impl Debug for KeyLogFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self.0.try_lock() {
            Ok(key_log_file) => write!(f, "{key_log_file:?}"),
            Err(_) => write!(f, "KeyLogFile {{ <locked> }}"),
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs, process};

    use super::*;

    #[test]
    fn test_env_var_is_not_set() {
        let mut inner = KeyLogFileInner::new(None);
        assert!(
            inner
                .try_write("label", b"random", b"secret")
                .is_ok()
        );
    }

    #[test]
    fn test_env_var_cannot_be_opened() {
        let mut inner = KeyLogFileInner::new(Some("/dev/does-not-exist".into()));
        assert!(
            inner
                .try_write("label", b"random", b"secret")
                .is_ok()
        );
    }

    #[test]
    fn test_env_var_cannot_be_written() {
        #[cfg(target_os = "linux")]
        const UNWRITABLE_FILE: &str = "/dev/full";

        #[cfg(target_os = "macos")]
        const UNWRITABLE_FILE: &str = "/dev/urandom";

        let mut inner = KeyLogFileInner::new(Some(UNWRITABLE_FILE.into()));
        assert!(
            inner
                .try_write("label", b"random", b"secret")
                .is_err()
        );
    }

    #[test]
    fn test_created_file_has_owner_only_permissions() {
        let path = env::temp_dir().join(format!(
            "rustls-keylog-perm-{}-{}",
            process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);

        let inner = KeyLogFileInner::new(Some(path.clone().into()));
        assert!(inner.file.is_some(), "key log file should open");

        let mode = fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        let _ = fs::remove_file(&path);

        assert_eq!(
            mode, 0o600,
            "SSLKEYLOGFILE must be created with mode 0o600, got {mode:#o}"
        );
    }
}
