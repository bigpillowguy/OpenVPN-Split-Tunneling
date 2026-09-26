use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub exe_path: String,
    pub exe_name: String,
    pub creation_time: u64,
}

const CACHE_LIMIT: usize = 2048;
const CACHE_IDLE: Duration = Duration::from_secs(30);

pub struct Resolver {
    cache: Mutex<HashMap<u32, (ProcessInfo, Instant)>>,
}

struct ProcessHandle(HANDLE);
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Reopen the current PID before using cached metadata. A PID alone is not
    /// an identity: Windows can reuse it as soon as the old process exits.
    pub fn resolve(&self, pid: u32) -> Option<ProcessInfo> {
        if pid == 0 || pid == 4 {
            return None;
        }
        let result = self.resolve_live(pid);
        if result.is_none() {
            self.cache.lock().unwrap().remove(&pid);
        }
        result
    }

    fn resolve_live(&self, pid: u32) -> Option<ProcessInfo> {
        let handle = ProcessHandle(
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?,
        );
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }
            .ok()?;
        if exited.dwLowDateTime != 0 || exited.dwHighDateTime != 0 {
            return None;
        }
        let creation_time = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
        let now = Instant::now();
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.len() >= CACHE_LIMIT {
                cache.retain(|_, (_, seen)| now.duration_since(*seen) < CACHE_IDLE);
            }
            if let Some((info, seen)) = cache.get_mut(&pid) {
                if info.creation_time == creation_time {
                    *seen = now;
                    return Some(info.clone());
                }
            }
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        }
        .ok()?;
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let info = ProcessInfo {
            exe_name: path.rsplit('\\').next().unwrap_or(&path).to_owned(),
            exe_path: path,
            creation_time,
        };
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(pid, (info.clone(), now));
        Some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_generation_does_not_return_old_executable() {
        let resolver = Resolver::new();
        let pid = std::process::id();
        let actual = resolver.resolve(pid).unwrap();
        resolver.cache.lock().unwrap().insert(
            pid,
            (
                ProcessInfo {
                    exe_path: "wrong.exe".into(),
                    exe_name: "wrong.exe".into(),
                    creation_time: actual.creation_time.wrapping_add(1),
                },
                Instant::now(),
            ),
        );
        let refreshed = resolver.resolve(pid).unwrap();
        assert_eq!(refreshed.exe_path, actual.exe_path);
        assert_eq!(refreshed.creation_time, actual.creation_time);
    }

    #[test]
    fn lookup_failures_are_not_cached() {
        let resolver = Resolver::new();
        assert!(resolver.resolve(u32::MAX).is_none());
        assert!(resolver.cache.lock().unwrap().is_empty());
    }
}
