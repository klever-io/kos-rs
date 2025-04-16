use parity_scale_codec::{Compact, Encode};

const SIGNED_FLAG: u8 = 0b1000_0000;
const TRANSACTION_VERSION: u8 = 4;
const PUBLIC_KEY_TYPE: u8 = 0x00;
const SIGNATURE_TYPE: u8 = 0x01;

/// Represents the payload of a Substrate extrinsic (transaction) that will be signed.
/// This structure contains all the necessary fields required for transaction signing.
#[allow(dead_code)]
pub struct ExtrinsicPayload {
    pub call: Vec<u8>,
    pub era: Vec<u8>,
    pub nonce: u32,
    pub tip: u8,
    pub mode: Option<u8>,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub genesis_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub metadata_hash: Option<u8>,
    pub app_id: Option<u32>,
}

impl ExtrinsicPayload {
    /// Encodes the payload using the Substrate transaction format.
    /// The format is: version + era + nonce + tip + call + params
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend(self.call.clone());
        encoded.extend(&self.era.clone());
        encoded.extend(Compact(self.nonce).encode());
        encoded.extend(Compact(self.tip).encode());

        // Use the app_id if it is set for AVAIL transactions, otherwise use the mode
        if let Some(app_id) = self.app_id {
            encoded.extend(Compact(app_id).encode());
        } else if let Some(mode) = self.mode {
            encoded.extend(mode.encode());
        }

        encoded.extend(&self.spec_version.encode());
        encoded.extend(&self.transaction_version.encode());
        encoded.extend(&self.genesis_hash);
        encoded.extend(&self.block_hash);

        // Use the metadata_hash if it is not set for AVAIL transactions
        if self.app_id.is_none() {
            if let Some(metadata_hash) = self.metadata_hash {
                encoded.push(metadata_hash);
            }
        }

        encoded
    }

    /// Encodes the payload with a signature using the Substrate transaction format.
    /// The format is: length + (version + signature + era + nonce + tip + call + params)
    pub fn encode_with_signature(&self, public_key: &[u8; 32], signature: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();

        encoded.push(SIGNED_FLAG | TRANSACTION_VERSION);

        encoded.push(PUBLIC_KEY_TYPE);
        encoded.extend_from_slice(public_key);

        encoded.push(SIGNATURE_TYPE);

        encoded.extend_from_slice(signature);

        encoded.extend_from_slice(&self.era);
        encoded.extend_from_slice(&Compact(self.nonce).encode());
        encoded.extend_from_slice(&Compact(self.tip).encode());

        // Use the app_id if it is set for AVAIL transactions, otherwise use the mode
        if let Some(app_id) = self.app_id {
            encoded.extend_from_slice(Compact(app_id).encode().as_slice());
        } else if let Some(mode) = self.mode {
            encoded.push(mode);
        }

        encoded.extend_from_slice(&self.call);

        let length = Compact(encoded.len() as u32).encode();
        let mut complete_encoded = Vec::with_capacity(length.len() + encoded.len());
        complete_encoded.extend_from_slice(&length);
        complete_encoded.extend_from_slice(&encoded);

        complete_encoded
    }
}
