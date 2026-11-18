// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Regular source files for vault additions; named pipes must never stall a writer.

use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

/// Follow ordinary source symlinks, but never block opening a FIFO. Validate
/// the opened handle, rather than a path that can change between stat and open.
pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a regular file: {}", path.display()),
        ));
    }
    Ok(file)
}

/// Read a regular file with the same nonblocking/type contract. Wipe any
/// partially read input on error and retain protected ownership through caller
/// validation on success.
pub(crate) fn read_regular(path: &Path) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut file = open_regular(path)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    crate::secret::read_to_end(&mut file, &mut bytes)?;
    Ok(bytes)
}

/// Process isolation makes FIFO regressions fail on a deadline even if an old
/// blocking open is reintroduced. Every path kills and reaps the child on drop.
#[cfg(all(test, unix))]
pub(crate) mod fifo_test {
    use super::*;
    use std::{
        process::{Child, Command},
        time::{Duration, Instant},
    };
    struct Worker(Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    pub(crate) fn child_path() -> Option<std::path::PathBuf> {
        std::env::var_os("AEROVAULT_FIFO_TEST_DIR").map(Into::into)
    }
    pub(crate) fn ready(dir: &Path) {
        std::fs::write(dir.join("ready"), b"").unwrap();
        let until = Instant::now() + Duration::from_secs(20);
        while !dir.join("go").exists() {
            assert!(Instant::now() < until, "parent did not release child");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(crate) fn run(test: &str, dir: &Path, site: &str, replace: impl FnOnce()) -> bool {
        let mut worker = Worker(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env("AEROVAULT_FIFO_TEST_DIR", dir)
                .env("AEROVAULT_FIFO_TEST_SITE", site)
                .spawn()
                .unwrap(),
        );
        let until = Instant::now() + Duration::from_secs(15);
        while !dir.join("ready").exists() {
            if worker.0.try_wait().unwrap().is_some() || Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        replace();
        std::fs::write(dir.join("go"), b"").unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = worker.0.try_wait().unwrap() {
                return status.success();
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn review_regular_read_keeps_protected_ownership_through_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short-plaintext");
        std::fs::write(&path, b"sensitive source").unwrap();
        let bytes: zeroize::Zeroizing<Vec<u8>> = super::read_regular(&path).unwrap();
        assert_eq!(bytes.as_slice(), b"sensitive source");
        // This compile-time return contract retains Zeroizing across caller
        // early returns; its Drop implementation performs the wipe.
    }
}
