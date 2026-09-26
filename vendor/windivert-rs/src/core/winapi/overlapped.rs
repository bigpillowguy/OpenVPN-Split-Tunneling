use std::ffi::c_void;

use windows::Win32::{
    Foundation::{ERROR_OPERATION_ABORTED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Threading::{ResetEvent, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

use super::tls::TlsIndex;

#[cfg(test)]
use mockall::automock;

pub(crate) struct Overlapped {
    // The address submitted to the kernel must not change when this wrapper moves.
    inner: Box<OVERLAPPED>,
    handle: HANDLE,
    pending: bool,
    completion: Option<Result<u32, windows::core::Error>>,
}

#[cfg_attr(test, automock)]
impl Overlapped {
    pub fn init(handle: &HANDLE, tls_index: &TlsIndex) -> Result<Self, windows::core::Error> {
        Ok(Self {
            inner: unsafe {
                let event = tls_index.get_or_init_event()?;
                ResetEvent(event)?;
                Box::new(OVERLAPPED {
                    hEvent: event,
                    ..Default::default()
                })
            },
            // SAFETY
            // This is safe since the cloned handle is only used internally during a single overlapped io that will block the thread
            handle: *handle,
            pending: false,
            completion: None,
        })
    }

    pub fn as_raw_mut(&mut self) -> *mut c_void {
        self.pending = true;
        self.inner.as_mut() as *mut OVERLAPPED as *mut c_void
    }

    /// A native call that failed without ERROR_IO_PENDING submitted no request.
    pub fn disarm(&mut self) {
        self.pending = false;
    }

    /// Method that waits until the overlapped event is signaled
    /// A timeout cancels and drains the request before the caller can free its buffers.
    /// A successful completion racing cancellation is still delivered to the caller.
    pub fn wait_for_object(&mut self, timeout_ms: u32) -> Result<bool, windows::core::Error> {
        unsafe {
            match WaitForSingleObject(self.inner.hEvent, timeout_ms) {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => self.cancel().map(|completion| completion.is_some()),
                _ => {
                    let wait_error = windows::core::Error::from_thread();
                    let _ = self.cancel();
                    Err(wait_error)
                }
            }
        }
    }

    pub fn get_result(&mut self) -> Result<u32, windows::core::Error> {
        if let Some(completion) = &self.completion {
            return completion.clone();
        }
        let mut written_bytes: u32 = 0;
        let completion = unsafe {
            GetOverlappedResult(self.handle, self.inner.as_ref(), &mut written_bytes, true)
        }
        .map(|()| written_bytes);
        self.pending = false;
        self.completion = Some(completion.clone());
        completion
    }

    pub fn cancel(&mut self) -> Result<Option<u32>, windows::core::Error> {
        // Cancellation is only a request, not completion. Even ERROR_NOT_FOUND
        // can mean completion won the race; always drain this exact OVERLAPPED.
        let _ = unsafe { CancelIoEx(self.handle, Some(self.inner.as_ref())) };
        match self.get_result() {
            Ok(length) => Ok(Some(length)),
            Err(error) if error.code() == ERROR_OPERATION_ABORTED.to_hresult() => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Overlapped {
    fn drop(&mut self) {
        if self.pending {
            let _ = self.cancel();
        }
    }
}

#[cfg(test)]
mod native_regressions;
