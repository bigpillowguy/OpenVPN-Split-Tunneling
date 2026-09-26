//! All native receive/open calls in this module are mocked; no driver is opened.
use super::*;
use serial_test::serial;
use windows::Win32::Foundation::{SetLastError, ERROR_ACCESS_DENIED};

// Matches WinDivert's encapsulated handle representation with a dummy test handle.
#[allow(clippy::arc_with_non_send_sync)]
fn setup<L: layer::WinDivertLayerTrait>(core: SysWrapper) -> WinDivert<L> {
    WinDivert {
        handle: Arc::new(HANDLE(1usize as *mut c_void)),
        tls_index: TlsIndex::alloc_tls().unwrap(),
        core,
        _layer: PhantomData,
    }
}

fn successful_receive(address_length: u32) -> SysWrapper {
    let mut core = SysWrapper::default();
    core.expect_WinDivertRecvEx().returning(
        move |_, data, length, _, _, address, address_len, _| unsafe {
            assert!(data.is_null());
            assert_eq!(length, 0);
            *address = WINDIVERT_ADDRESS::default();
            (*address).timestamp = 42;
            *address_len = address_length;
            SetLastError(ERROR_IO_PENDING);
            0
        },
    );
    core
}

#[test]
#[serial]
fn socket_zero_payload_preserves_event_address() {
    let context = Overlapped::init_context();
    context.expect().returning(|_, _| {
        let mut overlapped = Overlapped::default();
        overlapped.expect_as_raw_mut().returning(std::ptr::null_mut);
        overlapped.expect_wait_for_object().returning(|_| Ok(true));
        overlapped.expect_get_result().returning(|| Ok(0));
        Ok(overlapped)
    });
    let socket = setup::<SocketLayer>(successful_receive(ADDR_SIZE as u32));
    let packet = socket.recv_wait(100).unwrap().unwrap();
    assert!(packet.data.is_empty());
    assert_eq!(packet.address.event_timestamp(), 42);
    let flow = setup::<FlowLayer>(successful_receive(ADDR_SIZE as u32));
    assert!(flow.recv_wait(100).unwrap().unwrap().data.is_empty());
}

#[test]
#[serial]
fn zero_misaligned_and_oversized_address_batches_are_rejected() {
    let context = Overlapped::init_context();
    context.expect().returning(|_, _| {
        let mut overlapped = Overlapped::default();
        overlapped.expect_as_raw_mut().returning(std::ptr::null_mut);
        overlapped.expect_wait_for_object().returning(|_| Ok(true));
        overlapped.expect_get_result().returning(|| Ok(0));
        Ok(overlapped)
    });
    for length in [
        0,
        ADDR_SIZE as u32 - 1,
        ADDR_SIZE as u32 + 1,
        2 * ADDR_SIZE as u32,
    ] {
        let socket = setup::<SocketLayer>(successful_receive(length));
        assert!(matches!(
            socket.recv_wait(100),
            Err(WinDivertError::Recv(WinDivertRecvError::InvalidLength))
        ));
    }
}

#[test]
#[serial]
fn network_zero_payload_remains_an_error_and_oversized_result_is_rejected() {
    for length in [0, 9] {
        let context = Overlapped::init_context();
        context.expect().returning(move |_, _| {
            let mut overlapped = Overlapped::default();
            overlapped.expect_as_raw_mut().returning(std::ptr::null_mut);
            overlapped.expect_wait_for_object().returning(|_| Ok(true));
            overlapped.expect_get_result().returning(move || Ok(length));
            Ok(overlapped)
        });
        let mut core = SysWrapper::default();
        core.expect_WinDivertRecvEx()
            .returning(|_, _, _, _, _, address, _, _| unsafe {
                *address = WINDIVERT_ADDRESS::default();
                1
            });
        let network = setup::<NetworkLayer>(core);
        let mut buffer = [0; 8];
        assert!(network.recv_wait(&mut buffer, 100).is_err());
    }
}

#[test]
#[serial]
fn immediate_native_failure_is_disarmed_and_preserves_original_error() {
    let context = Overlapped::init_context();
    context.expect().returning(|_, _| {
        let mut overlapped = Overlapped::default();
        overlapped.expect_as_raw_mut().returning(std::ptr::null_mut);
        overlapped.expect_disarm().times(1).return_const(());
        Ok(overlapped)
    });
    let mut core = SysWrapper::default();
    core.expect_WinDivertRecvEx()
        .returning(|_, _, _, _, _, _, _, _| unsafe {
            SetLastError(ERROR_ACCESS_DENIED);
            0
        });
    let socket = setup::<SocketLayer>(core);
    let Err(WinDivertError::OSError(error)) = socket.recv_wait(100) else {
        panic!("native failure was lost");
    };
    assert_eq!(error.code(), ERROR_ACCESS_DENIED.to_hresult());
}

#[test]
fn zero_batch_is_rejected_before_native_io() {
    let socket = setup::<SocketLayer>(SysWrapper::default());
    assert!(matches!(
        socket.recv_wait_ex(0, 100),
        Err(WinDivertError::Recv(WinDivertRecvError::InvalidLength))
    ));
}
