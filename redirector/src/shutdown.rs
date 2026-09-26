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
        use windows::core::PCWSTR;
        use windows::Win32::System::Threading::{OpenEventW, SYNCHRONIZATION_SYNCHRONIZE};
        let handle = if let Some(name) = name {
            anyhow::ensure!(
                name.starts_with("Local\\VpnClient-") && !name.contains('\0'),
                "invalid shutdown event name"
            );
            let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            Some(unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, PCWSTR(name.as_ptr())) }?)
        } else {
            None
        };
        Ok(Self(handle))
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
