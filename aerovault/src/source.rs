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
    open_regular_with_policy(path, false)
}

pub(crate) fn open_regular_no_follow(path: &Path) -> io::Result<File> {
    open_regular_with_policy(path, true)
}

fn open_regular_with_policy(path: &Path, no_follow: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | if no_follow { libc::O_NOFOLLOW } else { 0 });
    }
    #[cfg(windows)]
    if no_follow {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(not(any(unix, windows)))]
    let _ = no_follow;
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a regular file: {}", path.display()),
        ));
    }
    Ok(file)
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

/// Memory regressions run in isolated Linux children; limits never affect the
/// parent test harness and every timeout kills and reaps the child.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod memory_test {
    pub(crate) fn limit() {
        let bound = 1536 * 1024 * 1024;
        let r = libc::rlimit {
            rlim_cur: bound,
            rlim_max: bound,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &r) }, 0);
    }
    pub(crate) fn run(test: &str, key: &str, path: &std::path::Path) {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env(key, path)
                .spawn()
                .unwrap(),
        );
        let end = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let status = loop {
            if let Some(s) = child.0.try_wait().unwrap() {
                break s;
            }
            assert!(std::time::Instant::now() < end, "memory child timed out");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.success(), "memory-limited child failed: {status}");
    }
}
