use anyhow::{Context, Result};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::job::Job;

pub struct SuspendedProcess {
    pub pid: u32,
    thread: HANDLE,
    process: HANDLE,
}

unsafe impl Send for SuspendedProcess {}
unsafe impl Sync for SuspendedProcess {}

pub fn spawn_suspended(job: &Job, exe: &str, args: &[String]) -> Result<SuspendedProcess> {
    let mut cmdline = quote(exe);
    for arg in args {
        cmdline.push(' ');
        cmdline.push_str(&quote(arg));
    }

    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
        .with_context(|| format!("CreateProcessW failed for: {}", cmdline))?;

        if let Err(e) = job.assign(pi.hProcess) {
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            return Err(e);
        }
    }

    Ok(SuspendedProcess {
        pid: pi.dwProcessId,
        thread: pi.hThread,
        process: pi.hProcess,
    })
}

pub fn resume(proc: SuspendedProcess) -> Result<()> {
    unsafe {
        if ResumeThread(proc.thread) == u32::MAX {
            let _ = CloseHandle(proc.thread);
            let _ = CloseHandle(proc.process);
            anyhow::bail!("ResumeThread failed");
        }
        let _ = CloseHandle(proc.thread);
        let _ = CloseHandle(proc.process);
    }
    Ok(())
}

fn quote(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    } else {
        s.to_string()
    }
}
