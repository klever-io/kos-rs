/// Unsigned single signer transactions prefix <https://xrpl.org/basic-data-types.html#hash-prefixes>
pub const HASH_PREFIX_UNSIGNED_TRANSACTION_SINGLE: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

pub const XRP_ALPHA: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub const OBJECT_NAME: &str = "STObject";
pub const OBJECT_END_MARKER_NAME: &str = "ObjectEndMarker";
pub const OBJECT_END_MARKER_BYTE: &[u8] = &[0xE1];

pub const ARRAY_END_MARKER: &[u8] = &[0xf1];
pub const ARRAY_END_MARKER_NAME: &str = "ArrayEndMarker";
pub const OBJECT_END_MARKER_ARRAY: &[u8] = &[0xE1];

pub const TRANSACTION_TYPE_PAYMENT: u16 = 0;

// #[repr(u16)]
// #[derive(Clone, Debug)]
// pub enum TransactionType {
//     // Discriminant values can be found at https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-binary-codec/src/enums/definitions.json
//     Payment = 0 as u16,
//     EscrowCreate = 1 as u16,
//     EscrowFinish = 2 as u16,
//     AccountSet = 3 as u16,
//     EscrowCancel = 4 as u16,
//     SetRegularKey = 5 as u16,
//     NickNameSet = 6 as u16,
//     OfferCreate = 7 as u16,
//     OfferCancel = 8 as u16,
//     Contract = 9 as u16,
//     TicketCreate = 10 as u16,
//     TicketCancel = 11 as u16,
//     SignerListSet = 12 as u16,
//     PaymentChannelCreate = 13 as u16,
//     PaymentChannelFund = 14 as u16,
//     PaymentChannelClaim = 15 as u16,
//     CheckCreate = 16 as u16,
//     CheckCash = 17 as u16,
//     CheckCancel = 18 as u16,
//     DepositPreauth = 19 as u16,
//     TrustSet = 20 as u16,
//     AccountDelete = 21 as u16,
//     SetHook = 22 as u16,
//     NFTokenMint = 25 as u16,
//     NFTokenBurn = 26 as u16,
//     NFTokenCreateOffer = 27 as u16,
//     NFTokenCancelOffer = 28 as u16,
//     NFTokenAcceptOffer = 29 as u16,
//     Clawback = 30 as u16,
//     AMMCreate = 35 as u16,
//     AMMDeposit = 36 as u16,
//     AMMWithdraw = 37 as u16,
//     AMMVote = 38 as u16,
//     AMMBid = 39 as u16,
//     AMMDelete = 40 as u16,
//     XChainCreateClaimID = 41 as u16,
//     XChainCommit = 42 as u16,
//     XChainClaim = 43 as u16,
//     XChainAccountCreateCommit = 44 as u16,
//     XChainAddClaimAttestation = 45 as u16,
//     XChainAddAccountCreateAttestation = 46 as u16,
//     XChainModifyBridge = 47 as u16,
//     XChainCreateBridge = 48 as u16,
//     DIDSet = 49 as u16,
//     DIDDelete = 50 as u16,
//     EnableAmendment = 100 as u16,
//     SetFee = 101 as u16,
//     UNLModify = 102 as u16,
// }
