use crate::chains::util::{
    byte_vectors_to_bytes, bytes_to_byte_vectors, private_key_from_vec, slice_from_vec,
};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::{sha224_digest, sha256_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use crate::KeyType;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use sha2::digest::Update;
use sha2::{Digest, Sha224};

const ACCOUNT_DOMAIN_SEPARATOR: &[u8] = b"\x0Aaccount-id";
const ASN1_ED25519_HEADER: [u8; 12] = [48u8, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];
const ACCOUNT_ID_BYTE: u8 = 0x0A;
const ICP_TAIL: u8 = 2;
const ACCOUNT_ID_STR: &str = "account-id";
#[allow(clippy::upper_case_acronyms)]
pub struct ICP {
    key_type: KeyType,
}

impl ICP {
    pub fn new(key_type: KeyType) -> Self {
        ICP { key_type }
    }

    pub fn new_from_string(key_type: String) -> Self {
        let key_type = match key_type.as_str() {
            "ed25519" => KeyType::ED25519,
            "secp256k1" => KeyType::SECP256K1,
            _ => panic!("Invalid key type"),
        };
        ICP { key_type }
    }

    fn crc32_checksum(&self, bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFFFFFF;
        for &byte in bytes {
            let lookup_index = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ TABLE_0[lookup_index];
        }
        !crc
    }
}

fn encode_pubkey_to_der(pubkey: &[u8]) -> Vec<u8> {
    let ec_public_key_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // Algo EC
    let secp256k1_oid = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]; // Curve secp256k1

    let mut algorithm_identifier = Vec::new();
    algorithm_identifier.extend_from_slice(&ec_public_key_oid);
    algorithm_identifier.extend_from_slice(&secp256k1_oid);

    let mut algorithm_sequence = Vec::new();
    algorithm_sequence.push(0x30); // SEQUENCE
    algorithm_sequence.push(algorithm_identifier.len() as u8);
    algorithm_sequence.extend_from_slice(&algorithm_identifier);

    let mut bitstring = Vec::new();
    bitstring.push(0x03); // BITSTRING

    let bitstring_len = pubkey.len() + 1;
    if bitstring_len < 128 {
        bitstring.push(bitstring_len as u8);
    } else {
        let len_bytes = if bitstring_len < 256 { 1 } else { 2 };
        bitstring.push(0x80 | len_bytes);
        if len_bytes == 1 {
            bitstring.push(bitstring_len as u8);
        } else {
            bitstring.push((bitstring_len >> 8) as u8);
            bitstring.push((bitstring_len & 0xFF) as u8);
        }
    }

    bitstring.push(0x00);
    bitstring.extend_from_slice(pubkey);

    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE

    let total_len = algorithm_sequence.len() + bitstring.len();

    if total_len < 128 {
        result.push(total_len as u8);
    } else {
        let len_bytes = if total_len < 256 { 1 } else { 2 };
        result.push(0x80 | len_bytes);
        if len_bytes == 1 {
            result.push(total_len as u8);
        } else {
            result.push((total_len >> 8) as u8);
            result.push((total_len & 0xFF) as u8);
        }
    }

    result.extend_from_slice(&algorithm_sequence);
    result.extend_from_slice(&bitstring);

    result
}

impl Chain for ICP {
    fn get_id(&self) -> u32 {
        31
    }

    fn get_name(&self) -> &str {
        "Internet Computer"
    }

    fn get_symbol(&self) -> &str {
        "ICP"
    }

    fn get_decimals(&self) -> u32 {
        8
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        if self.key_type == KeyType::ED25519 {
            let result = bip32::derive_ed25519(&seed, path)?;
            return Ok(Vec::from(result));
        }

        let result = bip32::derive(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        if self.key_type == KeyType::ED25519 {
            return format!("m/44'/223'/0'/0'/{index}");
        }

        format!("m/44'/223'/0'/0/{index}")
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;

        if self.key_type == KeyType::ED25519 {
            let pbk = Ed25519::public_from_private(&pvk_bytes)?;
            return Ok(pbk);
        }

        // First get the uncompressed public key (65 bytes total: 0x04 + X + Y)
        let raw_pubkey = Secp256K1::private_to_public_uncompressed(&pvk_bytes)?;
        pvk_bytes.fill(0);

        Ok(raw_pubkey.to_vec())
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if self.key_type == KeyType::ED25519 {
            let mut der = Vec::new();
            der.extend_from_slice(&ASN1_ED25519_HEADER);
            der.extend_from_slice(&public_key);

            let mut der_digest = sha224_digest(&der).to_vec();

            let mut new_digest = vec![ACCOUNT_ID_BYTE];
            new_digest.append(&mut ACCOUNT_ID_STR.as_bytes().to_vec());
            new_digest.append(der_digest.as_mut());
            new_digest.push(ICP_TAIL);
            new_digest.append(&mut vec![0u8; 32]);

            let out_digest = sha224_digest(&new_digest);
            let crc_calc = crc_calc_singletable(&out_digest);

            let mut addr_bytes: Vec<u8> = Vec::new();
            addr_bytes.append(&mut crc_calc.to_be_bytes().to_vec());
            addr_bytes.append(&mut out_digest.to_vec());

            let addr = hex::encode(addr_bytes);
            return Ok(addr);
        }

        let public_key = encode_pubkey_to_der(&public_key);

        let mut hasher = Sha224::new();
        Update::update(&mut hasher, &public_key);
        let hash_result = hasher.finalize();

        let mut principal_bytes = Vec::with_capacity(hash_result.len() + 1);
        principal_bytes.extend_from_slice(&hash_result);
        principal_bytes.push(0x02); // SELF_AUTHENTICATING_TAG

        let mut account_hasher = Sha224::new();
        Update::update(&mut account_hasher, ACCOUNT_DOMAIN_SEPARATOR);
        Digest::update(&mut account_hasher, &principal_bytes);

        let subaccount_bytes = [0u8; 32];
        Digest::update(&mut account_hasher, subaccount_bytes);

        let account_hash = account_hasher.finalize();

        let checksum = self.crc32_checksum(&account_hash);

        let mut final_bytes = Vec::with_capacity(32);
        final_bytes.extend_from_slice(&checksum.to_be_bytes());
        final_bytes.extend_from_slice(&account_hash);

        Ok(hex::encode(final_bytes))
    }
    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let tx_hash = tx.tx_hash.clone();
        let mut signatures = Vec::new();

        unsafe {
            web_sys::console::log_1(
                &format!("Signing transaction with {} hashes", tx_hash.len()).into(),
            )
        };

        let mut digest = tx_hash.to_vec();
        if self.key_type == KeyType::SECP256K1 {
            digest = sha256_digest(&tx_hash).to_vec();
        }
        let signature = self.sign_raw(private_key.clone(), digest)?;
        signatures.push(signature);

        tx.signature = byte_vectors_to_bytes(&signatures);

        if tx.tx_hash.is_empty() {
            tx.tx_hash = Vec::new();
        }

        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        let public_key = self.get_pbk(private_key.clone())?;

        let mut payload = message.clone();

        if self.key_type == KeyType::SECP256K1 {
            payload = sha256_digest(&message).to_vec();
        }

        let signature = self.sign_raw(private_key, payload)?;

        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&signature);
        signature_bytes.extend_from_slice(&public_key);

        Ok(signature_bytes)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let pvk_bytes = private_key_from_vec(&private_key)?;

        if self.key_type == KeyType::ED25519 {
            let sig = Ed25519::sign(&pvk_bytes, &payload)?;
            return Ok(sig);
        }

        let payload_bytes = slice_from_vec(&payload)?;
        let sig = Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        // Remove last byte (0x01) from signature
        let mut sig = sig.to_vec();
        sig.pop();

        Ok(sig)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::ICP
    }
}

const TABLE_0: [u32; 256] = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
];

pub fn crc_calc_singletable(buffer: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;

    for &byte in buffer.iter() {
        crc = TABLE_0[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }

    !crc
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_icp_get_address_ed25519() {
        let icp = ICP::new(KeyType::ED25519);

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = icp.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = icp.get_path(0, false);
        let pvk = icp.derive(seed, path).unwrap();
        let pbk = icp.get_pbk(pvk).unwrap();

        let addr = icp.get_address(pbk).unwrap();
        assert_eq!(
            addr,
            "11d238129427ef0e44d86bd27cb6d9da4d7e8934cb0306a93a540e657082d885"
        );
    }
    #[test]
    fn test_icp_get_address_secp256k1() {
        let icp = ICP::new(KeyType::SECP256K1);

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = icp.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = icp.get_path(0, false);
        let pvk = icp.derive(seed, path).unwrap();
        let pbk = icp.get_pbk(pvk).unwrap();

        let addr = icp.get_address(pbk).unwrap();
        assert_eq!(
            addr,
            "f24b889e8efba3d8008512e5f928af25be0fea33c9a44e161649f12912907cbd"
        );
    }

    #[test]
    fn test_icp_sign_message_ed25519() {
        let icp = ICP::new(KeyType::ED25519);

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = icp.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = icp.get_path(0, false);

        let pvk = icp.derive(seed, path).unwrap();

        let message = "test message".as_bytes().to_vec();
        let signature = icp.sign_message(pvk, message, true).unwrap();

        assert_eq!(
            hex::encode(signature),
            "db41e41de474e2cb6d997ae5aa5de9aa81512a19d1337881363a3c481431935992a118ba863b6d00612c638b5caf7bac65cb2cf31a7d30f9c5473fcb97bf620bc006bf0760963c13c1c1478adbc326b96338060f03487ebd1c3b261dbccd8daf"
        );
    }
    #[test]
    fn test_icp_sign_message_secp256k1() {
        let icp = ICP::new(KeyType::SECP256K1);

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = icp.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = icp.get_path(0, false);

        let pvk = icp.derive(seed, path).unwrap();

        let message = "test message".as_bytes().to_vec();
        let signature = icp.sign_message(pvk, message, true).unwrap();

        assert_eq!(
            hex::encode(signature),
            "72aa053da358a05c4db3f9c082022274605f6736ceb29f15a8ebdb46f072f6c76bb5ff8f7c8c3e5f7ba32116af449bb0308171f88515798a0e4a9efc8f0a03ff04abdb60eb7c96408414d1e251d41ca0ecf89a4541768cba7eed8174c53246d58c56031b23388bc7d275b4b26bf29137bdc181ae4d6b6f64f30db8d4bfd9222c27"
        );
    }

    #[test]
    fn test_icp_sign_raw_ed25519() {
        let icp = ICP::new(KeyType::ED25519);

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = icp.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = icp.get_path(0, false);

        let pvk = icp.derive(seed, path).unwrap();

        let message = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let signature = icp.sign_raw(pvk, message).unwrap();

        assert_eq!(
            hex::encode(signature),
            "71106543257919354ab03a2113a85fbfaffa9c0901b9333b9a0b9097927e68c7e2db2793a951a82dc8d9a4fd090ba97c7f7476a6db72a18c7c7e8a957f372707"
        );
    }
    #[test]
    fn test_icp_sign_raw_secp256k1() {
        let icp = ICP::new(KeyType::SECP256K1);

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = icp.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = icp.get_path(0, false);

        let pvk = icp.derive(seed, path).unwrap();

        let message = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let digest = sha256_digest(message.as_slice());

        let signature = icp.sign_raw(pvk, digest.to_vec()).unwrap();

        assert_eq!(
            hex::encode(signature),
            "063a468b4038d466ea5ccfb08b76c179d0e29a4f2c1d43d5ab831b8001ba450777199c5e6adc5a14583d2aa20bbef99ba4f2cec64457e7acf694cb291cbd3fe3"
        );
    }
}
