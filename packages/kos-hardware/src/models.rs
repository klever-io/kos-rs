use crate::DebugErrorHandler;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kos::chains::TxInfo;

#[repr(C)]
pub struct CNodeStruct {
    seed: *mut u8,
    seed_len: u32,
    pvk: *mut u8,
    pvk_len: u32,
    pbk: *mut u8,
    pbk_len: u32,
    path: *mut u8,
    path_len: u32,
}

fn read_to_vec(src: *const u8, src_len: u32) -> Vec<u8> {
    let mut result = Vec::with_capacity(src_len as usize);
    if src.is_null() {
        return result;
    }
    unsafe {
        for i in 0..src_len as usize {
            result.push(*src.add(i));
        }
    }
    result
}

fn write_to_memory(dst: *mut u8, dst_len: u32, src: *const u8, src_len: u32) {
    if dst.is_null() || src.is_null() || dst_len < src_len {
        return;
    }
    unsafe {
        for i in 0..src_len as usize {
            *dst.add(i) = *src.add(i);
        }
    }
}

impl CNodeStruct {
    pub fn write_seed(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.seed, self.seed_len, data, data_len);
        self.seed_len = data_len;
    }

    pub fn write_pvk(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.pvk, self.pvk_len, data, data_len);
        self.pvk_len = data_len;
    }

    pub fn write_pbk(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.pbk, self.pbk_len, data, data_len);
        self.pbk_len = data_len;
    }

    pub fn write_path(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.path, self.path_len, data, data_len);
        self.path_len = data_len;
    }

    pub fn read_seed(&self) -> Vec<u8> {
        read_to_vec(self.seed, self.seed_len)
    }

    pub fn read_pvk(&self) -> Vec<u8> {
        read_to_vec(self.pvk, self.pvk_len)
    }

    pub fn read_pbk(&self) -> Vec<u8> {
        read_to_vec(self.pbk, self.pbk_len)
    }

    pub fn read_path(&self) -> Vec<u8> {
        read_to_vec(self.path, self.path_len)
    }
}

#[repr(C)]
pub struct CBuffer {
    data: *mut u8,
    len: u32,
}

impl CBuffer {
    pub fn write(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.data, self.len, data, data_len);
        self.len = data_len;
    }

    pub fn read(&self) -> Vec<u8> {
        read_to_vec(self.data, self.len)
    }
}

#[repr(C)]
pub struct CTransaction {
    raw_data: *mut u8,
    raw_data_len: u32,
    tx_hash: *mut u8,
    tx_hash_len: u32,
    signature: *mut u8,
    signature_len: u32,
}

impl CTransaction {
    // Implement CTransaction similar to the other structs
    pub fn write_raw_data(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.raw_data, self.raw_data_len, data, data_len);
        self.raw_data_len = data_len;
    }

    pub fn write_tx_hash(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.tx_hash, self.tx_hash_len, data, data_len);
        self.tx_hash_len = data_len;
    }

    pub fn write_signature(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.signature, self.signature_len, data, data_len);
        self.signature_len = data_len;
    }

    pub fn read_raw_data(&self) -> Vec<u8> {
        read_to_vec(self.raw_data, self.raw_data_len)
    }

    pub fn read_tx_hash(&self) -> Vec<u8> {
        read_to_vec(self.tx_hash, self.tx_hash_len)
    }

    pub fn read_signature(&self) -> Vec<u8> {
        read_to_vec(self.signature, self.signature_len)
    }
}

#[repr(C)]
pub struct CTxInfo {
    pub sender: *mut u8,
    pub sender_len: u32,
    pub receiver: *mut u8,
    pub receiver_len: u32,
    pub value: f64,
    pub tx_type: u32,
}

impl CTxInfo {
    pub fn write_sender(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.sender, self.sender_len, data, data_len);
        self.sender_len = data_len;
    }

    pub fn write_receiver(&mut self, data: *const u8, data_len: u32) {
        write_to_memory(self.receiver, self.receiver_len, data, data_len);
        self.receiver_len = data_len;
    }

    pub fn read_sender(&self) -> Vec<u8> {
        read_to_vec(self.sender, self.sender_len)
    }

    pub fn read_receiver(&self) -> Vec<u8> {
        read_to_vec(self.receiver, self.receiver_len)
    }

    pub fn write(&mut self, tx_info: TxInfo) {
        self.write_sender(tx_info.sender.as_ptr(), tx_info.sender.len() as u32);
        self.write_receiver(tx_info.receiver.as_ptr(), tx_info.receiver.len() as u32);
        self.value = tx_info.value;
        self.tx_type = match tx_info.tx_type {
            crate::chains::TxType::Unknown => 1,
            crate::chains::TxType::Transfer => 2,
            crate::chains::TxType::TriggerContract => 3,
        };
    }

    #[allow(clippy::to_string_in_format_args)]
    pub fn to_tx_info(&self) -> TxInfo {
        let sender = String::from_utf8(self.read_sender()).unwrap_or_else(|e| {
            unsafe {
                DebugErrorHandler(format!("Invalid UTF-8 in sender: {}\0", e).as_ptr());
            }
            String::new()
        });

        let receiver = String::from_utf8(self.read_receiver()).unwrap_or_else(|e| {
            unsafe {
                DebugErrorHandler(format!("Invalid UTF-8 in receiver: {}\0", e).as_ptr());
            }
            String::new()
        });

        TxInfo {
            sender,
            receiver,
            value: self.value,
            tx_type: match self.tx_type {
                1 => crate::chains::TxType::Unknown,
                2 => crate::chains::TxType::Transfer,
                3 => crate::chains::TxType::TriggerContract,
                _ => crate::chains::TxType::Unknown,
            },
        }
    }
}

#[repr(C)]
pub struct RequestChainParams {
    pub chain: u32,
    pub is_custom: bool,
    pub chaincode: u32,
    pub chaincode_str: [u8; 64],
}

impl RequestChainParams {
    pub fn to_chain_type(&self) -> crate::chains::CustomChainType {
        if !self.is_custom {
            return crate::chains::CustomChainType::NotCustom(self.chain);
        }

        match self.chain {
            crate::chains::constants::ETH => {
                crate::chains::CustomChainType::CustomEth(self.chaincode)
            }
            crate::chains::constants::SUBSTRATE => {
                crate::chains::CustomChainType::CustomSubstrate(self.chaincode)
            }
            crate::chains::constants::COSMOS => crate::chains::CustomChainType::CustomCosmos(
                String::from_utf8(self.chaincode_str.to_vec()).unwrap_or_else(|_| String::new()),
            ),
            _ => crate::chains::CustomChainType::NotCustom(self.chain),
        }
    }
}
