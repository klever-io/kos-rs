use parity_scale_codec::{Compact, Encode};
use serde_json::Value;

const SIGNED_FLAG: u8 = 0b1000_0000;
const TRANSACTION_VERSION: u8 = 4;
const PUBLIC_KEY_TYPE: u8 = 0x00;

#[derive(Debug)]
enum PaymentExtension {
    ChargeAssetTxPayment(Option<u32>), // asset_id (None means use 0)
    ChargeTransactionPayment,          // don't add asset_id
    None,                              // use default behavior
}

/// Represents the payload of a Substrate extrinsic (transaction) that will be signed.
#[allow(dead_code)]
pub struct ExtrinsicPayload {
    pub call: Vec<u8>,
    pub era: Vec<u8>,
    pub nonce: u32,
    pub tip: u64,

    /// Optional asset ID for Asset Hub transactions. When set, the asset ID is encoded
    /// as part of the transaction payload for asset-specific operations.
    pub asset_id: Option<u32>,

    pub mode: Option<u8>,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub genesis_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub metadata_hash: Option<u8>,
    pub app_id: Option<u32>,

    pub signed_extensions: Option<Vec<u8>>,
}

impl ExtrinsicPayload {
    /// Encodes the payload using the Substrate transaction format.
    /// The default format is: version + era + nonce + tip + call + params
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend(self.call.clone());
        encoded.extend(&self.era.clone());
        encoded.extend(Compact(self.nonce).encode());
        encoded.extend(Compact(self.tip).encode());

        match self.get_payment_extension() {
            PaymentExtension::ChargeAssetTxPayment(asset_id_opt) => {
                // Use asset_id from extension, or 0 if None
                let asset_id = asset_id_opt.unwrap_or(0);
                encoded.extend(Compact(asset_id).encode());
            }
            PaymentExtension::ChargeTransactionPayment => {
                // Don't add asset_id for ChargeTransactionPayment
            }
            PaymentExtension::None => {
                // Default behavior: use self.asset_id if present
                if let Some(asset_id) = self.asset_id {
                    encoded.extend(Compact(asset_id).encode());
                }
            }
        }

        // Use the app_id if it is set for AVAIL transactions, otherwise use the mode
        if let Some(app_id) = self.app_id {
            encoded.extend(Compact(app_id).encode());
        }

        if let Some(mode) = self.mode {
            encoded.extend(mode.encode());
        }

        encoded.extend(&self.spec_version.encode());
        encoded.extend(&self.transaction_version.encode());
        encoded.extend(&self.genesis_hash);
        encoded.extend(&self.block_hash);

        if let Some(metadata_hash) = self.metadata_hash {
            encoded.push(metadata_hash);
        }

        encoded
    }

    /// Encodes the payload with a signature using the Substrate transaction format.
    /// The default format is: length + (version + signature + era + nonce + tip + call + params)
    pub fn encode_with_signature(&self, public_key: &[u8; 32], signature: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();

        encoded.push(SIGNED_FLAG | TRANSACTION_VERSION);

        encoded.push(PUBLIC_KEY_TYPE);
        encoded.extend_from_slice(public_key);

        encoded.extend_from_slice(signature);

        encoded.extend_from_slice(&self.era);
        encoded.extend_from_slice(&Compact(self.nonce).encode());
        encoded.extend_from_slice(&Compact(self.tip).encode());

        // Check signed extensions to determine payment method
        match self.get_payment_extension() {
            PaymentExtension::ChargeAssetTxPayment(asset_id_opt) => {
                // Use asset_id from extension, or 0 if None
                let asset_id = asset_id_opt.unwrap_or(0);
                encoded.extend(Compact(asset_id).encode());
            }
            PaymentExtension::ChargeTransactionPayment => {
                // Don't add asset_id for ChargeTransactionPayment
            }
            PaymentExtension::None => {
                if let Some(asset_id) = self.asset_id {
                    encoded.extend(Compact(asset_id).encode());
                }
            }
        }

        // Use the app_id if it is set for AVAIL transactions, otherwise use the mode
        if let Some(app_id) = self.app_id {
            encoded.extend_from_slice(Compact(app_id).encode().as_slice());
        }

        if let Some(mode) = self.mode {
            encoded.push(mode);
        }

        encoded.extend_from_slice(&self.call);

        let length = Compact(encoded.len() as u32).encode();
        let mut complete_encoded = Vec::with_capacity(length.len() + encoded.len());
        complete_encoded.extend_from_slice(&length);
        complete_encoded.extend_from_slice(&encoded);

        complete_encoded
    }

    /// Determines the payment extension type from signed_extensions
    fn get_payment_extension(&self) -> PaymentExtension {
        match parse_signed_extensions(&self.signed_extensions) {
            Ok(extension) => extension,
            Err(e) => {
                eprintln!("Error parsing signed extensions: {}", e);
                PaymentExtension::None
            }
        }
    }
}

/// Parses signed extensions and returns the payment extension type
fn parse_signed_extensions(
    signed_extensions: &Option<Vec<u8>>,
) -> Result<PaymentExtension, Box<dyn std::error::Error>> {
    let bytes = match signed_extensions {
        Some(b) => b,
        None => return Ok(PaymentExtension::None),
    };

    let json_str = std::str::from_utf8(bytes)?;
    let json: Value = serde_json::from_str(json_str)?;

    if let Some(charge_asset_value) = json.get("ChargeAssetTxPayment") {
        let asset_id = if charge_asset_value.is_null() {
            None
        } else if let Some(obj) = charge_asset_value.as_object() {
            obj.get("asset_id")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
        } else if let Some(num) = charge_asset_value.as_u64() {
            Some(num as u32)
        } else {
            None
        };

        return Ok(PaymentExtension::ChargeAssetTxPayment(asset_id));
    }

    if json.get("ChargeTransactionPayment").is_some() {
        return Ok(PaymentExtension::ChargeTransactionPayment);
    }

    Ok(PaymentExtension::None)
}
