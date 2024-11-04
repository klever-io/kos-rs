pub struct NONE;

impl Chain for NONE {
    fn get_name(&self) -> &str {
        return "NONE";
    }

    fn get_symbol(&self) -> &str {
        return "NONE";
    }

    fn get_decimals(&self) -> u32 {
        return 0;
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_tx_info(&self, raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }
}
