#![cfg_attr(feature = "ksafe", no_std)]
extern crate alloc;
pub mod chains;
pub mod crypto;

#[cfg(feature = "ksafe")]
use core::alloc::{GlobalAlloc, Layout};

#[cfg(feature = "ksafe")]
#[allow(dead_code)]
struct FreeRtosAllocator;

#[cfg(feature = "ksafe")]
#[allow(dead_code)]
extern "C" {
    fn pvPortMalloc(size: u32) -> *mut u8; // Using u32 instead of libc::size_t
    fn vPortFree(ptr: *mut u8);
    fn HardFault_Handler();
    fn DebugErrorHandler(log: *const u8);
}

#[cfg(feature = "ksafe")]
unsafe impl GlobalAlloc for FreeRtosAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        pvPortMalloc(layout.size() as u32) // Cast to u32
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        vPortFree(ptr);
    }
}

#[cfg(all(feature = "ksafe", not(test)))]
#[global_allocator]
static ALLOCATOR: FreeRtosAllocator = FreeRtosAllocator;

#[cfg(all(feature = "ksafe", not(test), not(feature = "not-ksafe")))]
#[panic_handler]
unsafe fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    HardFault_Handler();
    loop {}
}

#[derive(PartialEq, Eq)]
pub enum KeyType {
    ED25519,
    SECP256K1,
    SR25519,
}
