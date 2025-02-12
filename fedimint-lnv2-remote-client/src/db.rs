use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};

use crate::messages::{
    AcceptedContract, ContractId, DlcAccept, DlcSign, OfferedContract, SignedContract,
};

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    OfferedContract = 0xb1,
    AcceptedContract = 0xb2,
    SignedContract = 0xb3,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OfferedContractKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OfferedContractKeyPrefix;

impl_db_record!(
    key = OfferedContractKey,
    value = OfferedContract,
    db_prefix = DbKeyPrefix::OfferedContract,
);
impl_db_lookup!(
    key = OfferedContractKey,
    query_prefix = OfferedContractKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct AcceptedContractKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct AcceptedContractKeyPrefix;

impl_db_record!(
    key = AcceptedContractKey,
    value = AcceptedContract,
    db_prefix = DbKeyPrefix::AcceptedContract,
);
impl_db_lookup!(
    key = AcceptedContractKey,
    query_prefix = AcceptedContractKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SignedContractKey(pub ContractId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SignedContractKeyPrefix;

impl_db_record!(
    key = SignedContractKey,
    value = SignedContract,
    db_prefix = DbKeyPrefix::SignedContract,
);
impl_db_lookup!(
    key = SignedContractKey,
    query_prefix = SignedContractKeyPrefix
);

/// Inserts an `OfferedContract` into the database.
/// This is idempotent for a given `offered_contract`.
/// If `Ok(())` is returned, the `OfferedContract` was
/// inserted or already exists. If an error is returned,
/// it means that a different `offered_contract` already
/// exists with the same contract ID. Either way, the
/// same value is always returned for a given
/// `offered_contract`.
pub async fn insert_offered_contract(
    dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
    offered_contract: OfferedContract,
) -> anyhow::Result<()> {
    let contract_id = offered_contract.dlc_offer.contract_id.clone();

    if let Some(existing_signed_contract) = dbtx
        .get_value(&SignedContractKey(contract_id.clone()))
        .await
    {
        return if existing_signed_contract.accepted_contract.offered_contract != offered_contract {
            Err(anyhow::anyhow!(
                "Different signed contract already exists with the same contract ID"
            ))
        } else {
            Ok(())
        };
    }

    if let Some(existing_accepted_contract) = dbtx
        .get_value(&AcceptedContractKey(contract_id.clone()))
        .await
    {
        return if existing_accepted_contract.offered_contract != offered_contract {
            Err(anyhow::anyhow!(
                "Different accepted contract already exists with the same contract ID"
            ))
        } else {
            Ok(())
        };
    }

    if let Some(existing_offered_contract) = dbtx
        .get_value(&OfferedContractKey(contract_id.clone()))
        .await
    {
        return if existing_offered_contract != offered_contract {
            Err(anyhow::anyhow!(
                "Different offered contract already exists with the same contract ID"
            ))
        } else {
            Ok(())
        };
    }

    // If we've reached this point, there are no existing
    // contract offers with the same contract ID.
    dbtx.insert_entry(&OfferedContractKey(contract_id), &offered_contract)
        .await;

    Ok(())
}

/// Inserts an `AcceptedContract` into the database.
/// This is idempotent for a given `accepted_contract` _if_
/// `insert_offered_contract()` was called with an offer
/// that has the same contract ID. Otherwise, an error is
/// always returned.
pub async fn insert_accepted_contract(
    dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
    dlc_accept: DlcAccept,
) -> anyhow::Result<OfferedContract> {
    let contract_id = dlc_accept.contract_id.clone();

    if let Some(existing_signed_contract) = dbtx
        .get_value(&SignedContractKey(contract_id.clone()))
        .await
    {
        return if existing_signed_contract.accepted_contract.dlc_accept != dlc_accept {
            Err(anyhow::anyhow!(
                "Different signed contract already exists with the same contract ID"
            ))
        } else {
            Ok(existing_signed_contract.accepted_contract.offered_contract)
        };
    }

    if let Some(existing_accepted_contract) = dbtx
        .get_value(&AcceptedContractKey(contract_id.clone()))
        .await
    {
        return if existing_accepted_contract.dlc_accept != dlc_accept {
            Err(anyhow::anyhow!(
                "Different accepted contract already exists with the same contract ID"
            ))
        } else {
            Ok(existing_accepted_contract.offered_contract)
        };
    }

    if let Some(existing_offered_contract) = dbtx
        .remove_entry(&OfferedContractKey(contract_id.clone()))
        .await
    {
        dbtx.insert_entry(
            &AcceptedContractKey(contract_id.clone()),
            &AcceptedContract {
                offered_contract: existing_offered_contract.clone(),
                dlc_accept,
            },
        )
        .await;

        return Ok(existing_offered_contract);
    }

    Err(anyhow::anyhow!(
        "No offered contract found with the given contract ID"
    ))
}

/// Inserts a `SignedContract` into the database.
/// This is idempotent for a given `signed_contract` _if_
/// `insert_accepted_contract()` was called with an accept
/// that has the same contract ID. Otherwise, an error is
/// always returned.
pub async fn insert_signed_contract(
    dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
    dlc_sign: DlcSign,
) -> anyhow::Result<AcceptedContract> {
    let contract_id = dlc_sign.contract_id.clone();

    if let Some(existing_signed_contract) = dbtx
        .get_value(&SignedContractKey(contract_id.clone()))
        .await
    {
        return if existing_signed_contract.dlc_sign != dlc_sign {
            Err(anyhow::anyhow!(
                "Different signed contract already exists with the same contract ID"
            ))
        } else {
            Ok(existing_signed_contract.accepted_contract)
        };
    }

    if let Some(existing_accepted_contract) = dbtx
        .remove_entry(&AcceptedContractKey(contract_id.clone()))
        .await
    {
        dbtx.insert_entry(
            &SignedContractKey(contract_id.clone()),
            &SignedContract {
                accepted_contract: existing_accepted_contract.clone(),
                dlc_sign,
            },
        )
        .await;

        return Ok(existing_accepted_contract);
    }

    Err(anyhow::anyhow!(
        "No accepted contract found with the given contract ID"
    ))
}
