use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};

use crate::messages::{ContractId, DlcAccept, DlcOffer, DlcSign};

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcOfferAndMetadata {
    pub offer: DlcOffer,
    pub role: ContractRole,
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub enum ContractRole {
    Offerer = 0,
    Acceptor = 1,
}

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    DlcOfferAndMetadata = 0xb1,
    DlcAccept = 0xb2,
    DlcSign = 0xb3,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcOfferAndMetadataKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcOfferAndMetadataKeyPrefix;

impl_db_record!(
    key = DlcOfferAndMetadataKey,
    value = DlcOfferAndMetadata,
    db_prefix = DbKeyPrefix::DlcOfferAndMetadata,
);
impl_db_lookup!(
    key = DlcOfferAndMetadataKey,
    query_prefix = DlcOfferAndMetadataKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcAcceptKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcAcceptKeyPrefix;

impl_db_record!(
    key = DlcAcceptKey,
    value = DlcAccept,
    db_prefix = DbKeyPrefix::DlcAccept,
);
impl_db_lookup!(key = DlcAcceptKey, query_prefix = DlcAcceptKeyPrefix);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcSignKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DlcSignKeyPrefix;

impl_db_record!(
    key = DlcSignKey,
    value = DlcSign,
    db_prefix = DbKeyPrefix::DlcSign,
);
impl_db_lookup!(key = DlcSignKey, query_prefix = DlcSignKeyPrefix);
