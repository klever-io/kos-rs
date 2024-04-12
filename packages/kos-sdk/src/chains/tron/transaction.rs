use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct TRXTransaction {
    #[serde(flatten)]
    pub transaction: kos_proto::tron::Transaction,
    pub raw_data_hex: String,
}
