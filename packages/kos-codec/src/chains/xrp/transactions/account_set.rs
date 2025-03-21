use crate::chains::xrp::transactions::{
    transaction_base::TransactionCommon, Serialize, Transaction,
};
use kos::chains::ChainError;

use xrpl::core::{
    binarycodec::{
        definitions::{load_definition_map, DefinitionHandler, FieldInstance},
        types::{blob::Blob, Hash128, Hash256, XRPLType},
        Serialization,
    },
    BinarySerializer,
};

#[derive(Debug)]
pub struct AccountSetTransaction {
    pub common: TransactionCommon,
    pub flags: Option<u32>,
    pub clear_flag: Option<u32>,
    pub domain: Option<Blob>,
    pub email_hash: Option<Hash128>,
    pub message_key: Option<Blob>,
    pub nft_token_minter: Option<Blob>,
    pub set_flag: Option<Blob>,
    pub transfer_rate: Option<u32>,
    pub ticket_size: Option<u8>,
    pub wallet_locator: Option<Hash256>,
    pub wallet_size: Option<u32>,
}

impl AccountSetTransaction {
    pub fn from(buffer: Vec<(FieldInstance, Vec<u8>)>) -> Result<Self, ChainError> {
        let mut flags: Option<u32> = None;
        let mut clear_flag: Option<u32> = None;
        let mut domain: Option<Blob> = None;
        let mut email_hash: Option<Hash128> = None;
        let mut message_key: Option<Blob> = None;
        let mut nft_token_minter: Option<Blob> = None;
        let mut set_flag: Option<Blob> = None;
        let mut transfer_rate: Option<u32> = None;
        let mut ticket_size: Option<u8> = None;
        let mut wallet_locator: Option<Hash256> = None;
        let mut wallet_size: Option<u32> = None;

        let common: TransactionCommon = TransactionCommon::from(buffer.clone())?;

        for value in buffer {
            match value.0.name.as_str() {
                "Flags" => {
                    flags = Some(u32::from_be_bytes(value.1.try_into().unwrap()));
                }
                "ClearFlag" => {
                    clear_flag = Some(u32::from_be_bytes(value.1.try_into().unwrap()));
                }
                "Domain" => {
                    domain = Some(Blob::new(Some(&value.1)).unwrap());
                }
                "EmailHash" => {
                    email_hash = Some(Hash128::new(Some(value.1.as_ref())).unwrap());
                }
                "MessageKey" => {
                    message_key = Some(Blob::new(Some(&value.1)).unwrap());
                }
                "NFTokenMinter" => {
                    nft_token_minter = Some(Blob::new(Some(&value.1)).unwrap());
                }
                "SetFlag" => {
                    set_flag = Some(Blob::new(Some(&value.1)).unwrap());
                }
                "TransferRate" => {
                    transfer_rate = Some(u32::from_be_bytes(value.1.try_into().unwrap()));
                }
                "TickSize" => {
                    ticket_size = Some(u8::from_be_bytes(value.1.try_into().unwrap()));
                }
                "WalletLocator" => {
                    wallet_locator = Some(Hash256::new(Some(value.1.as_ref())).unwrap());
                }
                "WalletSize" => {
                    wallet_size = Some(u32::from_be_bytes(value.1.try_into().unwrap()));
                }
                _ => {}
            }
        }

        Ok(AccountSetTransaction {
            common,
            flags,
            clear_flag,
            domain,
            email_hash,
            message_key,
            nft_token_minter,
            set_flag,
            transfer_rate,
            ticket_size,
            wallet_locator,
            wallet_size,
        })
    }
}

impl Transaction for AccountSetTransaction {
    fn common_mut(&mut self) -> &mut TransactionCommon {
        &mut self.common
    }
}

impl Serialize for AccountSetTransaction {
    fn serialize(&self) -> Result<Vec<u8>, ChainError> {
        let mut fields_and_value: Vec<(FieldInstance, Vec<u8>)> = Vec::new();

        let definition_map: &xrpl::core::binarycodec::definitions::DefinitionMap =
            load_definition_map();

        let common_serialized = self.common.serialize();

        fields_and_value.extend_from_slice(common_serialized.as_ref());

        if let Some(field_instance) = definition_map.get_field_instance("Flags") {
            if let Some(flags) = self.flags {
                fields_and_value
                    .extend_from_slice(&[(field_instance, flags.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("ClearFlag") {
            if let Some(clear_flag) = self.clear_flag {
                fields_and_value
                    .extend_from_slice(&[(field_instance, clear_flag.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Domain") {
            if let Some(domain) = self.domain.as_ref() {
                fields_and_value.extend_from_slice(&[(field_instance, domain.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("EmailHash") {
            if let Some(email_hash) = self.email_hash.as_ref() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, email_hash.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("MessageKey") {
            if let Some(message_key) = self.message_key.as_ref() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, message_key.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("NFTokenMinter") {
            if let Some(nft_token_minter) = self.nft_token_minter.as_ref() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, nft_token_minter.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("SetFlag") {
            if let Some(set_flag) = self.set_flag.as_ref() {
                fields_and_value.extend_from_slice(&[(field_instance, set_flag.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("TransferRate") {
            if let Some(transfer_rate) = self.transfer_rate {
                fields_and_value
                    .extend_from_slice(&[(field_instance, transfer_rate.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("TickSize") {
            if let Some(ticket_size) = self.ticket_size {
                fields_and_value
                    .extend_from_slice(&[(field_instance, ticket_size.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("WalletLocator") {
            if let Some(wallet_locator) = self.wallet_locator.clone() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, wallet_locator.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("WalletSize") {
            if let Some(wallet_size) = self.wallet_size {
                fields_and_value
                    .extend_from_slice(&[(field_instance, wallet_size.to_be_bytes().to_vec())]);
            }
        }
        let mut serializer = BinarySerializer::new();

        fields_and_value.sort_by_key(|fv| fv.0.ordinal);
        for fv in fields_and_value {
            serializer.write_field_and_value(fv.0, fv.1.as_ref(), false);
        }

        Ok(serializer)
    }
}
