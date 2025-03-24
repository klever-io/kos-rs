#![no_std]
#![allow(clippy::to_string_in_format_args)]
use kos::chains;

mod models;

extern crate alloc;

use crate::models::{CBuffer, CNodeStruct, CTransaction, CTxInfo, RequestChainParams};
use alloc::format;
use alloc::string::{String, ToString};

#[allow(unused_imports)]
use core::alloc::GlobalAlloc;

#[allow(dead_code)]
struct FreeRtosAllocator;
#[allow(dead_code)]
extern "C" {
    fn pvPortMalloc(size: u32) -> *mut u8; // Using u32 instead of libc::size_t
    fn vPortFree(ptr: *mut u8);
    fn HardFault_Handler();

    fn DebugErrorHandler(log: *const u8);
}

#[no_mangle]
pub extern "C" fn rust_add(a: u32, b: u32) -> u32 {
    a + b
}

#[no_mangle]
pub extern "C" fn rs_derive(chain: &mut RequestChainParams, node: &mut CNodeStruct) -> bool {
    unsafe {
        let path = node.read_path();
        let seed = node.read_seed();

        let c = match chains::get_chain_by_params(chain.to_chain_type()) {
            Some(c) => c,
            None => {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
                return false;
            }
        };

        let pvk = c.derive(seed, String::from_utf8_unchecked(path)).unwrap();

        node.write_pvk(pvk.as_ptr(), pvk.len() as u32);
    }

    true
}

#[no_mangle]
pub extern "C" fn rs_get_pbk(chain: &mut RequestChainParams, node: &mut CNodeStruct) -> bool {
    let pvk = node.read_pvk();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => return false,
    };

    let pbk = match c.get_pbk(pvk) {
        Ok(pbk) => pbk,
        Err(_) => return false,
    };

    node.write_pbk(pbk.as_ptr(), pbk.len() as u32);

    true
}

#[no_mangle]
pub extern "C" fn rs_get_addr(
    chain: &mut RequestChainParams,
    node: &mut CNodeStruct,
    result: &mut CBuffer,
) -> bool {
    let pbk = node.read_pbk();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => return false,
    };

    let addr = match c.get_address(pbk) {
        Ok(a) => a,
        Err(_) => return false,
    };

    result.write(addr.as_ptr(), addr.len() as u32);

    true
}

#[no_mangle]
pub extern "C" fn rs_sign_tx(
    chain: &mut RequestChainParams,
    node: &mut CNodeStruct,
    tx: &mut CTransaction,
    output: &mut CBuffer,
) -> bool {
    let pvk = node.read_pvk();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };

    let raw_tx = tx.read_raw_data();
    let tx_hash = tx.read_tx_hash();
    let signature = tx.read_signature();
    let to_sign = chains::Transaction {
        raw_data: raw_tx,
        tx_hash,
        signature,
        options: None,
    };

    let signed = match c.sign_tx(pvk, to_sign) {
        Ok(t) => t,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error signing tx: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };

    tx.write_tx_hash(signed.tx_hash.as_ptr(), signed.tx_hash.len() as u32);
    tx.write_signature(signed.signature.as_ptr(), signed.signature.len() as u32);

    output.write(signed.raw_data.as_ptr(), signed.raw_data.len() as u32);

    true
}

#[no_mangle]
pub extern "C" fn rs_sign_raw_tx(
    chain: &mut RequestChainParams,
    node: &mut CNodeStruct,
    payload: &mut CBuffer,
    sig: &mut CBuffer,
) -> bool {
    let pvk = node.read_pvk();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };

    let payload = payload.read();

    let signature = match c.sign_raw(pvk, payload) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error signing raw tx: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };

    sig.write(signature.as_ptr(), signature.len() as u32);
    true
}

#[no_mangle]
pub extern "C" fn rs_sign_message(
    chain: &mut RequestChainParams,
    node: &mut CNodeStruct,
    message: &mut CBuffer,
    sig: &mut CBuffer,
) -> bool {
    let pvk = node.read_pvk();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };

    let message = message.read();

    let signature = match c.sign_message(pvk, message) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error signing message: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };

    sig.write(signature.as_ptr(), signature.len() as u32);
    true
}

#[no_mangle]
pub extern "C" fn rs_get_chain_name(chain: &mut RequestChainParams, result: &mut CBuffer) -> bool {
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };

    result.write(c.get_name().as_ptr(), c.get_name().len() as u32);

    true
}

#[no_mangle]
pub extern "C" fn rs_get_chain_symbol(
    chain: &mut RequestChainParams,
    result: &mut CBuffer,
) -> bool {
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };

    result.write(c.get_symbol().as_ptr(), c.get_symbol().len() as u32);

    true
}

#[no_mangle]
pub extern "C" fn rs_get_tx_info(
    chain: &mut RequestChainParams,
    tx: &mut CTransaction,
    result: &mut CTxInfo,
) -> bool {
    let raw_tx = tx.read_raw_data();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };

    let tx_info = match c.get_tx_info(raw_tx) {
        Ok(t) => t,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error getting tx info: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };

    result.write(tx_info);

    true
}

#[no_mangle]
pub extern "C" fn rs_mnemonic_to_seed(
    chain: &mut RequestChainParams,
    mnemonic: &mut CBuffer,
    password: &mut CBuffer,
    result: &mut CBuffer,
) -> bool {
    let mnemonic = mnemonic.read();
    let password = password.read();
    let c = match chains::get_chain_by_params(chain.to_chain_type()) {
        Some(c) => c,
        None => {
            unsafe {
                DebugErrorHandler(format!("Chain not found: {} \0", chain.chain).as_ptr());
            }
            return false;
        }
    };
    let mnemonic_string = match String::from_utf8(mnemonic) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error on mnemonic: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };
    let password_string = match String::from_utf8(password) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error on password: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };

    let seed = match c.mnemonic_to_seed(mnemonic_string, password_string) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                DebugErrorHandler(format!("Error on derive: {} \0", e.to_string()).as_ptr());
            }
            return false;
        }
    };

    result.write(seed.as_ptr(), seed.len() as u32);

    true
}

#[no_mangle]
pub extern "C" fn rs_tx_info_to_json(info: &mut CTxInfo, result: &mut CBuffer) -> bool {
    let tx_info = info.to_tx_info();
    let json = tiny_json_rs::encode(tx_info);

    result.write(json.as_ptr(), json.len() as u32);
    true
}

pub const VERSION: &str = "Library Version: 0.1.1";

#[no_mangle]
pub extern "C" fn get_version() -> *const u8 {
    VERSION.as_ptr()
}

#[cfg(test)]
mod tests {}
