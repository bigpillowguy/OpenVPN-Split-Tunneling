use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared by async coordination and bounded WinDivert receive loops.
#[derive(Clone, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub struct ExternalStop(Option<windows::Win32::Foundation::HANDLE>);
impl ExternalStop {
    pub fn open(name: Option<&str>) -> anyhow::Result<Self> {
        use anyhow::Context;
        use windows::core::PCWSTR;
        use windows::Win32::System::Threading::{OpenEventW, SYNCHRONIZATION_SYNCHRONIZE};
        let handle = if let Some(name) = name {
            anyhow::ensure!(
                name.starts_with("Local\\VpnClient-") && !name.contains('\0'),
                "invalid shutdown event name"
            );
            let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            Some(
                unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, PCWSTR(name.as_ptr())) }
                    .context("open UI shutdown event")?,
            )
        } else {
            None
        };
        Ok(Self(handle))
    }

    pub async fn wait_for_request(&self) -> anyhow::Result<()> {
        use anyhow::Context;
        if self.0.is_some() {
            // The UI starts a child without a console and supplies this event.
            // Its lifetime must not depend on registering any console handler.
            tracing::info!("waiting for UI shutdown event");
            self.wait().await
        } else {
            tracing::info!("waiting for console shutdown signal");
            tokio::signal::ctrl_c()
                .await
                .context("console shutdown signal")
        }
    }

    pub async fn wait(&self) -> anyhow::Result<()> {
        use windows::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::WaitForSingleObject;
        let Some(handle) = self.0 else {
            return std::future::pending().await;
        };
        loop {
            let result = unsafe { WaitForSingleObject(handle, 0) };
            if result == WAIT_OBJECT_0 {
                return Ok(());
            }
            if result == WAIT_FAILED {
                return Err(windows::core::Error::from_thread().into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
impl Drop for ExternalStop {
    fn drop(&mut self) {
        if let Some(handle) = self.0 {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_stop_child() {
        let Ok(name) = std::env::var("REDIRECTOR_TEST_SHUTDOWN_EVENT") else {
            return;
        };
        let path = std::env::var("REDIRECTOR_TEST_LOG_PATH").unwrap();
        crate::diagnostics::init(Some(std::path::Path::new(&path))).unwrap();
        let stop = ExternalStop::open(Some(&name)).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(10), stop.wait_for_request())
                    .await
                    .unwrap()
                    .unwrap();
            });
        // A worker panic must remain diagnosable in the same headless launch.
        assert!(
            std::thread::spawn(|| panic!("diagnostic panic test sentinel"))
                .join()
                .is_err()
        );
        tracing::info!("headless stop completed");
    }

    #[test]
    fn ui_event_stops_create_no_window_child_without_driver_or_console_input() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Threading::{CreateEventW, SetEvent};

        struct Event(HANDLE);
        impl Drop for Event {
            fn drop(&mut self) {
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        struct Log(std::path::PathBuf);
        impl Drop for Log {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let name = format!("Local\\VpnClient-test-{suffix}");
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let event =
            Event(unsafe { CreateEventW(None, true, false, PCWSTR(wide.as_ptr())) }.unwrap());
        let log = Log(std::env::temp_dir().join(format!("redirector-headless-test-{suffix}.log")));
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "shutdown::tests::headless_stop_child",
                    "--nocapture",
                ])
                .env("REDIRECTOR_TEST_SHUTDOWN_EVENT", &name)
                .env("REDIRECTOR_TEST_LOG_PATH", &log.0)
                .env("RUST_LOG", "info")
                .creation_flags(0x08000000) // CREATE_NO_WINDOW, as used by the UI Job launcher.
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if std::fs::read_to_string(&log.0)
                .unwrap_or_default()
                .contains("waiting for UI shutdown event")
            {
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "headless child exited before waiting"
            );
            assert!(
                Instant::now() < deadline,
                "headless child did not start waiting"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        unsafe { SetEvent(event.0) }.unwrap();
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "headless child failed: {status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "headless child did not stop on its event"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let text = std::fs::read_to_string(&log.0).unwrap();
        assert!(text.contains("headless stop completed"));
        assert!(text.contains("diagnostic panic test sentinel"));
        assert!(!text.contains("waiting for console shutdown signal"));
    }

    #[test]
    fn stop_reaches_blocking_worker() {
        let signal = Shutdown::new();
        let worker_signal = signal.clone();
        let worker = std::thread::spawn(move || {
            while !worker_signal.is_stopped() {
                std::thread::yield_now();
            }
        });
        signal.stop();
        worker.join().unwrap();
    }
}
