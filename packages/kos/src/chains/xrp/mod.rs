pub mod constants;
mod models;
mod transactions;

use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::b58::custom_b58enc;
use crate::crypto::bip32;
use crate::crypto::hash::{ripemd160_digest, sha256_digest, sha512_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use xrpl::core::binarycodec::types::{blob::Blob, XRPLType};

#[allow(clippy::upper_case_acronyms)]
pub(crate) struct XRP {}

impl XRP {
    pub fn new() -> Self {
        XRP {}
    }
}

impl XRP {
    fn prepare_message(message: Vec<u8>) -> [u8; 32] {
        let sha512_hash: [u8; 64] = sha512_digest(&message);

        let mut sha512_half: [u8; 32] = [0; 32];
        sha512_half.copy_from_slice(&sha512_hash[..32]);

        sha512_half
    }

    fn prepare_transaction(message: Vec<u8>) -> [u8; 32] {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&constants::HASH_PREFIX_UNSIGNED_TRANSACTION_SINGLE);
        buffer.extend_from_slice(message.as_ref());

        let sha512_hash: [u8; 64] = sha512_digest(&buffer);

        let mut sha512_half: [u8; 32] = [0; 32];
        sha512_half.copy_from_slice(&sha512_hash[..32]);

        sha512_half
    }
}

impl Chain for XRP {
    fn get_id(&self) -> u32 {
        4
    }

    fn get_name(&self) -> &str {
        "Ripple"
    }

    fn get_symbol(&self) -> &str {
        "XRP"
    }

    fn get_decimals(&self) -> u32 {
        6
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(pvk.to_vec())
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/144'/0'/0/{}", index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pk_bytes: [u8; 32] = [0; 32];
        pk_bytes.copy_from_slice(&private_key[..32]);

        let pbk = Secp256K1::private_to_public_compressed(&pk_bytes)?;
        Ok(pbk.to_vec())
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);

        let to_base_58 = [vec![0], hash[..].to_vec()].concat();
        let checksum = sha256_digest(&sha256_digest(&to_base_58));
        let checksum_bytes = checksum[..4].to_vec();
        let to_base_58 = [&to_base_58[..], &checksum_bytes[..]].concat();

        let res = custom_b58enc(&to_base_58, constants::XRP_ALPHA);
        let addr = String::from_utf8(res)?;
        Ok(addr)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let mut transaction = transactions::decode_factory(tx.raw_data)?;

        let pbk = self.get_pbk(private_key.clone())?;

        transaction.common_mut().signing_pub_key = Some(Blob::new(Some(pbk.as_ref())).unwrap());

        let buff = transaction.serialize()?;

        let msg_to_sign = XRP::prepare_transaction(buff).to_vec();
        tx.signature = self.sign_raw(private_key, msg_to_sign.clone())?;

        transaction.common_mut().txn_signature =
            Some(Blob::new(Some(tx.signature.as_ref())).unwrap());

        tx.raw_data = transaction.serialize()?;

        Ok(tx)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let prepared_msg: [u8; 32] = XRP::prepare_message(message);
        self.sign_raw(private_key, prepared_msg.to_vec())
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = Secp256K1::sign_der(&payload_bytes, &pvk_bytes)?;
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::base64::simple_base64_decode;
    use alloc::string::{String, ToString};

    #[test]
    fn test_get_addr() {
        let xrp = super::XRP::new();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = xrp.get_path(0, false);

        let seed = xrp.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = xrp.derive(seed, path).unwrap();
        let pbk = xrp.get_pbk(pvk).unwrap();
        let addr = xrp.get_address(pbk).unwrap();

        assert_eq!(addr, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3");
    }

    #[test]
    fn test_sig_message() {
        let xrp = super::XRP::new();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = xrp.get_path(0, false);
        let seed = xrp.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = xrp.derive(seed, path).unwrap();

        let message = "test message".as_bytes().to_vec();
        let signature = xrp.sign_message(pvk, message).unwrap();

        assert_eq!(hex::encode(signature).to_uppercase(), "3045022100E10177E86739A9C38B485B6AA04BF2B9AA00E79189A1132E7172B70F400ED1170220566BD64AA3F01DDE8D99DFFF0523D165E7DD2B9891ABDA1944E2F3A52CCCB83A");
    }

    #[test]
    fn test_sig_transaction() {
        let xrp = super::XRP::new();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = xrp.get_path(0, false);
        let seed = xrp.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = xrp.derive(seed, path).unwrap();

        let raw_tx = simple_base64_decode("EgAAJAOJPiQuAAAE0mFAAAAAAAAAAWhAAAAAAAAACoEUT3VxzuEHlw82sSKFzBfkTBIcoK6DFIkT5tGhrFdnm0ML+ClCV9S7P1/f").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let tx_signed = xrp.sign_tx(pvk, tx).unwrap();

        assert_eq!(hex::encode(tx_signed.raw_data.clone()).to_uppercase(), "1200002403893E242E000004D261400000000000000168400000000000000A7321031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE74463044022051CA6A9AB7EB0F9994A9B6A838CA49EE7AEEF2B776098A6DD8C7CEA6BF6CB6870220294FFF13FCC7F1ABC24410711243C2084FFC3FC05952B541EA4F759D7A69713881144F7571CEE107970F36B12285CC17E44C121CA0AE83148913E6D1A1AC57679B430BF8294257D4BB3F5FDF");

        assert_eq!(hex::encode(tx_signed.signature).to_uppercase(), "3044022051CA6A9AB7EB0F9994A9B6A838CA49EE7AEEF2B776098A6DD8C7CEA6BF6CB6870220294FFF13FCC7F1ABC24410711243C2084FFC3FC05952B541EA4F759D7A697138");
    }

    #[test]
    fn test_decode_payment_tx() {
        // Example frmo https://github.com/XRPLF/xrpl-dev-portal/blob/master/_code-samples/tx-serialization/js/test-cases/tx3-binary.txt
        let raw_tx = simple_base64_decode("EgAAIgAAAAAkAAADSiAbAJcXvmFAAAAAAJiWgGhAAAAAAAAADGnUVkuWSoRawAAAAAAAAAAAAAAAAFVTRAAAAAAAadM7GNUzhfijGFUWwu2l3tuKxcZzIQN58Xz6D/11GBgVlL5p/poQRx1t4fQFXG0nRq/Wz4mInnRHMEUCIQDVXtGVP4YK3BvFzZk6u5J/SBVqyjHGRzeGX09P9tAVqAIgYwcE0r0JyOmfJgkMJfEbKPXZahNQRUQCws7ZKzn/26+BFGnTOxjVM4X4oxhVFsLtpd7bisXGgxRp0zsY1TOF+KMYVRbC7aXe24rFxvnqfAZjbGllbnR9B3J0MS4xLjHh8QESAfOxmXVi/XQrVNTr3qHWrqPUkGuPEAAAAAAAAAAAAAAAAAAAAAAAAAAA/wFLTpwG8kKWB097xI+SqXkWxtxeqQHdOcZQqW7aSDNOcMxKhbiy6FAs0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();

        let transaction = transactions::decode_factory(raw_tx.clone()).unwrap();

        let serialized = transaction.serialize().unwrap();

        assert_eq!(hex::encode(serialized).to_uppercase(), "1200002200000000240000034A201B009717BE61400000000098968068400000000000000C69D4564B964A845AC0000000000000000000000000555344000000000069D33B18D53385F8A3185516C2EDA5DEDB8AC5C673210379F17CFA0FFD7518181594BE69FE9A10471D6DE1F4055C6D2746AFD6CF89889E74473045022100D55ED1953F860ADC1BC5CD993ABB927F48156ACA31C64737865F4F4FF6D015A80220630704D2BD09C8E99F26090C25F11B28F5D96A1350454402C2CED92B39FFDBAF811469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6831469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6F9EA7C06636C69656E747D077274312E312E31E1F1011201F3B1997562FD742B54D4EBDEA1D6AEA3D4906B8F100000000000000000000000000000000000000000FF014B4E9C06F24296074F7BC48F92A97916C6DC5EA901DD39C650A96EDA48334E70CC4A85B8B2E8502CD310000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_encode_payment_tx() {
        let raw_tx = simple_base64_decode("EgAAIgAAAAAkAAADSiAbAJcXvmFAAAAAAJiWgGhAAAAAAAAADGnUVkuWSoRawAAAAAAAAAAAAAAAAFVTRAAAAAAAadM7GNUzhfijGFUWwu2l3tuKxcZzIQN58Xz6D/11GBgVlL5p/poQRx1t4fQFXG0nRq/Wz4mInnRHMEUCIQDVXtGVP4YK3BvFzZk6u5J/SBVqyjHGRzeGX09P9tAVqAIgYwcE0r0JyOmfJgkMJfEbKPXZahNQRUQCws7ZKzn/26+BFGnTOxjVM4X4oxhVFsLtpd7bisXGgxRp0zsY1TOF+KMYVRbC7aXe24rFxvnqfAZjbGllbnR9B3J0MS4xLjHh8QESAfOxmXVi/XQrVNTr3qHWrqPUkGuPEAAAAAAAAAAAAAAAAAAAAAAAAAAA/wFLTpwG8kKWB097xI+SqXkWxtxeqQHdOcZQqW7aSDNOcMxKhbiy6FAs0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();

        let transaction = transactions::decode_factory(raw_tx.clone()).unwrap();

        let buff = transaction.serialize().unwrap();

        assert_eq!(hex::encode(raw_tx).to_uppercase(), hex::encode_upper(buff));
    }

    #[test]
    fn test_decode_account_set_tx() {
        let raw_tx = simple_base64_decode("EgADIoAAAAAkAAAAFyAbAIaVU2hAAAAAAAAADHMhAviersdmezDzPQaHu6hsP+KgjMpAqRhsW94tqm+pejfYdEcwRQIhAL3gmh9mcEA/NBwhp3zzW6R+Rc3pdAluGqX8OYEdgmnnAiA9YCkbmifx3Kupz13tMHtPIyI+C28VaZHbYB37nEHOHHcKcmlwcGxlLmNvbYEUXnsRJSP2jS9eh5206sUcZpimkwQ=").unwrap();

        let transaction = transactions::decode_factory(raw_tx.clone()).unwrap();

        let serialized = transaction.serialize().unwrap();

        assert_eq!(hex::encode(serialized).to_uppercase(), "12000322800000002400000017201B0086955368400000000000000C732102F89EAEC7667B30F33D0687BBA86C3FE2A08CCA40A9186C5BDE2DAA6FA97A37D874473045022100BDE09A1F6670403F341C21A77CF35BA47E45CDE974096E1AA5FC39811D8269E702203D60291B9A27F1DCABA9CF5DED307B4F23223E0B6F156991DB601DFB9C41CE1C770A726970706C652E636F6D81145E7B112523F68D2F5E879DB4EAC51C6698A69304");
    }

    #[test]
    fn test_encode_account_set_tx() {
        let raw_tx = simple_base64_decode("EgADIoAAAAAkAAAAFyAbAIaVU2hAAAAAAAAADHMhAviersdmezDzPQaHu6hsP+KgjMpAqRhsW94tqm+pejfYdEcwRQIhAL3gmh9mcEA/NBwhp3zzW6R+Rc3pdAluGqX8OYEdgmnnAiA9YCkbmifx3Kupz13tMHtPIyI+C28VaZHbYB37nEHOHHcKcmlwcGxlLmNvbYEUXnsRJSP2jS9eh5206sUcZpimkwQ=").unwrap();

        let transaction = transactions::decode_factory(raw_tx.clone()).unwrap();

        let buff = transaction.serialize().unwrap();

        assert_eq!(hex::encode(raw_tx).to_uppercase(), hex::encode_upper(buff));
    }

    #[test]
    fn test_decode_trust_set_tx() {
        // Example from https://github.com/sephynox/xrpl-rust/blob/0bb773469e17d10763c339f440fcc0c112cfcd4a/src/core/binarycodec/test_data/data-driven-tests.json
        let raw_tx = simple_base64_decode("EgAUIgACAAAkAAAALGPWQ41+pMaAAAAAAAAAAAAAAAAAAFdDRwAAAAAAgyKXvvWJ1Z+cA6hPkg+NkSjMHORoQAAAAAAAAAyBFL5sMHMq4zzyrzNEzoFyprkwAYPj").unwrap();

        let transaction = transactions::decode_factory(raw_tx.clone()).unwrap();

        let serialized = transaction.serialize().unwrap();

        assert_eq!(hex::encode(serialized).to_uppercase(), "1200142200020000240000002C63D6438D7EA4C680000000000000000000000000005743470000000000832297BEF589D59F9C03A84F920F8D9128CC1CE468400000000000000C8114BE6C30732AE33CF2AF3344CE8172A6B9300183E3");
    }

    #[test]
    fn test_encode_trust_set_tx() {
        let raw_tx = simple_base64_decode("EgAUIgACAAAkAAAALGPWQ41+pMaAAAAAAAAAAAAAAAAAAFdDRwAAAAAAgyKXvvWJ1Z+cA6hPkg+NkSjMHORoQAAAAAAAAAyBFL5sMHMq4zzyrzNEzoFyprkwAYPj").unwrap();

        let transaction = transactions::decode_factory(raw_tx.clone()).unwrap();

        let buff = transaction.serialize().unwrap();

        assert_eq!(hex::encode(raw_tx).to_uppercase(), hex::encode_upper(buff));
    }
}
