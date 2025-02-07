use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::ContractId;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    UnfundedContract = 0xb1,
    FundedContract = 0xb2,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct UnfundedContractKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct UnfundedContractKeyPrefix;

impl_db_record!(
    key = UnfundedContractKey,
    value = ContractAndClaimerPubkey,
    db_prefix = DbKeyPrefix::UnfundedContract,
);
impl_db_lookup!(
    key = UnfundedContractKey,
    query_prefix = UnfundedContractKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FundedContractKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct FundedContractKeyPrefix;

impl_db_record!(
    key = FundedContractKey,
    value = ContractAndClaimerPubkey,
    db_prefix = DbKeyPrefix::FundedContract,
);
impl_db_lookup!(
    key = FundedContractKey,
    query_prefix = FundedContractKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ContractAndClaimerPubkey {
    pub contract: IncomingContract,
    pub claimer_pk: PublicKey,
}
