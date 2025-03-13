use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Debug)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct MessageAddressTableLookup {
    /// Address lookup table account key
    pub account_key: Vec<u8>,
    /// List of indexes used to load writable account addresses
    pub writable_indexes: Vec<u8>,
    /// List of indexes used to load readonly account addresses
    pub readonly_indexes: Vec<u8>,
}

#[derive(Debug)]
pub struct Message {
    pub version: String,
    pub header: MessageHeader,
    pub account_keys: Vec<Vec<u8>>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

#[derive(Debug)]
pub struct SolanaTransaction {
    pub signatures: Vec<Vec<u8>>,
    pub message: Message,
}

const MESSAGE_VERSION_LEGACY: &str = "legacy";
const MESSAGE_VERSION_V0: &str = "v0";

impl Message {
    pub fn decode(input: &[u8]) -> Result<Self, prost::DecodeError> {
        let mut position = 0;

        // 1. Header is exactly 3 bytes
        if input.len() < 3 {
            return Err(prost::DecodeError::new("Invalid message header length"));
        }

        let mut version: String = String::from(MESSAGE_VERSION_LEGACY);
        if input[0] > 127 {
            let v = input[0];
            let value = v - 128;
            version = format!("v{}", value);
            position += 1;
        }

        let header = MessageHeader {
            num_required_signatures: input[position],
            num_readonly_signed_accounts: input[position + 1],
            num_readonly_unsigned_accounts: input[position + 2],
        };
        position += 3;

        // 2. Account addresses array
        let num_accounts = input[position] as usize;
        position += 1;

        let mut account_keys = Vec::with_capacity(num_accounts);
        for _ in 0..num_accounts {
            let mut key = vec![0u8; 32];
            key.copy_from_slice(&input[position..position + 32]);
            account_keys.push(key);
            position += 32;
        }

        // 3. Recent blockhash
        let mut recent_blockhash = [0u8; 32];
        recent_blockhash.copy_from_slice(&input[position..position + 32]);
        position += 32;

        // 4. Instructions
        let num_instructions = input[position] as usize;
        position += 1;

        let mut instructions = Vec::with_capacity(num_instructions);
        for _ in 0..num_instructions {
            // Program ID index
            let program_id_index = input[position];
            position += 1;

            // Account indexes
            let num_accounts = input[position] as usize;
            position += 1;
            let mut accounts = vec![0u8; num_accounts];
            accounts.copy_from_slice(&input[position..position + num_accounts]);
            position += num_accounts;

            // Instruction data
            let data_len = input[position] as usize;
            position += 1;
            let mut data = vec![0u8; data_len];
            data.copy_from_slice(&input[position..position + data_len]);
            position += data_len;

            instructions.push(CompiledInstruction {
                program_id_index,
                accounts,
                data,
            });
        }

        // Address Lookup Tables
        let mut compiled_address_lookup_tables : Vec<MessageAddressTableLookup> = vec![];
        if version == String::from(MESSAGE_VERSION_V0) {
            let address_lookuptable_count:u8 = input[position];
            position += 1;
    
            for _ in 0..address_lookuptable_count {
                let mut address_lookup_table_pubkey: Vec<u8> = vec![0u8; 32];
                address_lookup_table_pubkey.copy_from_slice(&input[position..position + 32]);
                position += 32;

                let writable_account_idx_count: u8 = input[position];
                position += 1;

                let mut writable_account_idx_list: Vec<u8> = vec![];
                for _ in 0..writable_account_idx_count {
                    writable_account_idx_list.push(input[position]);
                    position += 1;
                }

                let read_only_account_idx_count: u8 = input[position];
                position += 1;

                let mut read_only_account_idx_list: Vec<u8> = vec![];
                for _ in 0..read_only_account_idx_count {
                    read_only_account_idx_list.push(input[position]);
                    position += 1;
                }

                compiled_address_lookup_tables.push(
                    MessageAddressTableLookup {
                        account_key: address_lookup_table_pubkey,
                        writable_indexes: writable_account_idx_list,
                        readonly_indexes: read_only_account_idx_list,
                    }
                );
            }
        }

        Ok(Message {
            version,
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups: compiled_address_lookup_tables,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();

        // 0. add version only if version is not legacy
        if self.version.len() > 0 && self.version != String::from(MESSAGE_VERSION_LEGACY) {
            let v_string = self.version[1..].to_string();
            let v = v_string.parse::<u8>().unwrap();
            output.push(v + 128);
        }

        // 1. Header (3 bytes)
        output.push(self.header.num_required_signatures);
        output.push(self.header.num_readonly_signed_accounts);
        output.push(self.header.num_readonly_unsigned_accounts);

        // 2. Account addresses array
        output.push(self.account_keys.len() as u8);
        for key in &self.account_keys {
            output.extend_from_slice(key);
        }

        // 3. Recent blockhash
        output.extend_from_slice(&self.recent_blockhash);

        // 4. Instructions
        output.push(self.instructions.len() as u8);
        for instruction in &self.instructions {
            output.push(instruction.program_id_index);
            output.push(instruction.accounts.len() as u8);
            output.extend_from_slice(&instruction.accounts);
            output.push(instruction.data.len() as u8);
            output.extend_from_slice(&instruction.data);
        }

        // 5. address table lookups
        if self.version.len() > 0 && self.version != String::from(MESSAGE_VERSION_LEGACY) {
            output.push(self.address_table_lookups.len() as u8);
            for key in &self.address_table_lookups {
                output.extend_from_slice(&key.account_key);
                output.push(key.writable_indexes.len() as u8);
                output.extend_from_slice(&key.writable_indexes);
                output.push(key.readonly_indexes.len() as u8);
                output.extend_from_slice(&key.readonly_indexes);
            }
        }

        output
    }
}

impl SolanaTransaction {
    pub fn decode(input: &[u8]) -> Result<Self, prost::DecodeError> {
        let mut position = 0;

        let num_signatures = input[position] as usize;
        position += 1;

        let mut signatures = Vec::with_capacity(num_signatures);
        for _ in 0..num_signatures {
            let mut signature = vec![0u8; 64];
            signature.copy_from_slice(&input[position..position + 64]);
            signatures.push(signature);
            position += 64;
        }

        let message = Message::decode(&input[position..])?;

        Ok(SolanaTransaction {
            signatures,
            message,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let signature_count = encode_varint(self.signatures.len() as u64);

        let mut output = Vec::with_capacity(
            signature_count.len() + self.signatures.len() * 64 + self.message.encode().len(),
        );

        output.extend_from_slice(&signature_count);

        for signature in &self.signatures {
            output.extend_from_slice(signature);
        }

        output.extend_from_slice(&self.message.encode());

        output
    }
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
    buf
}