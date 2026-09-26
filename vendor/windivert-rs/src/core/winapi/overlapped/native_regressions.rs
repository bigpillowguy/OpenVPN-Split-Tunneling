//! Real Windows overlapped I/O against private named pipes; no WinDivert APIs.
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::atomic::{AtomicU64, Ordering},
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{ERROR_IO_PENDING, ERROR_PIPE_CONNECTED},
        Storage::FileSystem::{ReadFile, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_INBOUND},
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
    },
};

static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

fn pipe() -> (OwnedHandle, File) {
    let name = format!(
        r"\\.\pipe\VpnClient-overlapped-test-{}-{}",
        std::process::id(),
        NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
    );
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            None,
        )
    };
    assert!(
        !handle.is_invalid(),
        "{}",
        windows::core::Error::from_thread()
    );
    let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    let client = std::thread::spawn(move || OpenOptions::new().write(true).open(name).unwrap());
    let tls = TlsIndex::alloc_tls().unwrap();
    let mut connect = Overlapped::init(&handle, &tls).unwrap();
    let result = unsafe { ConnectNamedPipe(handle, Some(connect.as_raw_mut().cast())) };
    match result {
        Ok(()) => {
            connect.get_result().unwrap();
        }
        Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => connect.disarm(),
        Err(error) => {
            assert_eq!(error.code(), ERROR_IO_PENDING.to_hresult());
            assert!(connect.wait_for_object(3000).unwrap());
            connect.get_result().unwrap();
        }
    }
    (owned, client.join().unwrap())
}

fn submit(handle: HANDLE, overlapped: &mut Overlapped, buffer: &mut [u8]) {
    let error = unsafe {
        ReadFile(
            handle,
            Some(buffer),
            None,
            Some(overlapped.as_raw_mut().cast()),
        )
    }
    .unwrap_err();
    assert_eq!(error.code(), ERROR_IO_PENDING.to_hresult());
}

#[test]
fn timeout_drains_cancelled_request_and_does_not_cancel_another_read() {
    let (server, mut client) = pipe();
    let handle = HANDLE(server.as_raw_handle());
    let first_tls = TlsIndex::alloc_tls().unwrap();
    let second_tls = TlsIndex::alloc_tls().unwrap();
    let mut first_buffer = [0u8; 1];
    let mut second_buffer = [0u8; 1];
    let mut first = Overlapped::init(&handle, &first_tls).unwrap();
    let mut second = Overlapped::init(&handle, &second_tls).unwrap();
    submit(handle, &mut first, &mut first_buffer);
    submit(handle, &mut second, &mut second_buffer);
    assert!(!first.wait_for_object(0).unwrap());
    assert!(!first.pending);
    assert_eq!(
        first.get_result().unwrap_err().code(),
        ERROR_OPERATION_ABORTED.to_hresult()
    );
    assert_ne!(first.inner.Internal, 0x103); // STATUS_PENDING must be gone before buffers can drop.
    drop(first);
    first_buffer[0] = 99;
    client.write_all(b"x").unwrap();
    assert!(second.wait_for_object(3000).unwrap());
    assert_eq!(second.get_result().unwrap(), 1);
    assert_eq!(second_buffer, *b"x");
    assert_eq!(first_buffer, [99]);
}

#[test]
fn moving_wrapper_preserves_native_address_and_completed_cancel_race_returns_data() {
    let (server, mut client) = pipe();
    let handle = HANDLE(server.as_raw_handle());
    let tls = TlsIndex::alloc_tls().unwrap();
    let mut buffer = [0u8; 1];
    let mut overlapped = Overlapped::init(&handle, &tls).unwrap();
    let original_address = overlapped.inner.as_ref() as *const OVERLAPPED;
    submit(handle, &mut overlapped, &mut buffer);
    let mut moved = Box::new(overlapped);
    assert_eq!(original_address, moved.inner.as_ref() as *const OVERLAPPED);
    client.write_all(b"y").unwrap();
    assert_eq!(
        unsafe { WaitForSingleObject(moved.inner.hEvent, 3000) },
        WAIT_OBJECT_0
    );
    // Cancellation is now too late (ERROR_NOT_FOUND); the successful read must survive.
    assert_eq!(moved.cancel().unwrap(), Some(1));
    assert_eq!(moved.get_result().unwrap(), 1);
    assert_eq!(buffer, *b"y");
}

#[test]
fn dropping_pending_wrapper_drains_before_buffer_is_reused() {
    let (server, mut client) = pipe();
    let handle = HANDLE(server.as_raw_handle());
    let tls = TlsIndex::alloc_tls().unwrap();
    let mut buffer = [0u8; 1];
    let mut abandoned = Overlapped::init(&handle, &tls).unwrap();
    submit(handle, &mut abandoned, &mut buffer);
    drop(abandoned);
    buffer[0] = 55;
    // Reusing the TLS event and buffer is safe only once the previous I/O completed.
    let mut next = Overlapped::init(&handle, &tls).unwrap();
    submit(handle, &mut next, &mut buffer);
    client.write_all(b"z").unwrap();
    assert!(next.wait_for_object(3000).unwrap());
    assert_eq!(next.get_result().unwrap(), 1);
    assert_eq!(buffer, *b"z");
}
