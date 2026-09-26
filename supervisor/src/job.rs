use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectAssociateCompletionPortInformation,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED};

const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
const JOB_OBJECT_MSG_EXIT_PROCESS: u32 = 7;
const JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS: u32 = 8;

#[derive(Debug, Clone, Copy)]
pub enum JobEvent {
    NewProcess(u32),
    ExitProcess(u32),
    ActiveZero,
}

#[derive(Clone, Copy)]
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

pub struct Job {
    handle: HANDLE,
}

impl Job {
    pub fn create() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(None, None) }.context("CreateJobObjectW failed")?;

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of_val(&info) as u32,
            )
            .context("SetInformationJobObject(ExtendedLimit) failed")?;
        }

        Ok(Self { handle })
    }

    pub fn assign(&self, process: HANDLE) -> Result<()> {
        unsafe { AssignProcessToJobObject(self.handle, process) }
            .context("AssignProcessToJobObject failed")?;
        Ok(())
    }

    pub fn start_event_loop(&self) -> Result<mpsc::Receiver<JobEvent>> {
        let iocp = unsafe {
            CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1)
                .context("CreateIoCompletionPort failed")?
        };

        let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: self.handle.0,
            CompletionPort: iocp,
        };
        unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectAssociateCompletionPortInformation,
                &assoc as *const _ as *const _,
                std::mem::size_of_val(&assoc) as u32,
            )
            .context("SetInformationJobObject(AssociateCompletionPort) failed")?;
        }

        let (tx, rx) = mpsc::channel();
        let iocp = SendHandle(iocp);
        thread::spawn(move || pump(iocp, tx));
        Ok(rx)
    }
}

fn pump(iocp: SendHandle, tx: mpsc::Sender<JobEvent>) {
    loop {
        let mut bytes: u32 = 0;
        let mut key: usize = 0;
        let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();

        let r = unsafe {
            GetQueuedCompletionStatus(iocp.0, &mut bytes, &mut key, &mut overlapped, u32::MAX)
        };
        if r.is_err() {
            tracing::warn!("GetQueuedCompletionStatus failed: {:?}", r);
            break;
        }

        let pid = overlapped as usize as u32;
        let event = match bytes {
            JOB_OBJECT_MSG_NEW_PROCESS => JobEvent::NewProcess(pid),
            JOB_OBJECT_MSG_EXIT_PROCESS | JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS => {
                JobEvent::ExitProcess(pid)
            }
            JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => JobEvent::ActiveZero,
            other => {
                tracing::debug!("ignored job message {} for pid {}", other, pid);
                continue;
            }
        };

        if tx.send(event).is_err() {
            break;
        }
        if matches!(event, JobEvent::ActiveZero) {
            break;
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
