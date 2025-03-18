use xrpl::core::binarycodec::types::{account_id::AccountId, blob::Blob, Amount, Hash256, STArray};

#[derive(Debug)]
pub struct TransactionCommon {
    pub account: AccountId,
    pub fee: Option<Amount>,
    pub sequence: Option<u32>,
    pub account_txn_id: Option<Hash256>,
    pub last_ledger_sequence: Option<u32>,
    pub memos: Option<STArray>,
    pub network_id: Option<u32>,
    pub source_tag: Option<u32>,
    pub signing_pub_key: Option<Blob>,
    pub ticket_sequence: Option<u32>,
    pub txn_signature: Option<Blob>,
}
