#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

mod api;
#[cfg(feature = "cli")]
mod cli;
mod db;
mod messages;
mod remote_receive_sm;

use std::collections::BTreeMap;
use std::hash::Hash;
use std::time::Duration;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1;
use db::{ContractRole, DlcAcceptKey, DlcOfferAndMetadata, DlcOfferAndMetadataKey, DlcSignKey};
use ddk_manager::contract::contract_info::ContractInfo;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleConsensusVersion, ModuleInit,
    MultiApiVersion,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount, BitcoinHash};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, LightningModuleTypes, MODULE_CONSENSUS_VERSION,
};
use fedimint_mint_client::OOBNotes;
use messages::{ContractId, DlcAccept, DlcOffer, DlcSign, PartyParams};
use schnorr_fun::fun::marker::Normal;
use schnorr_fun::fun::Point;
use schnorr_fun::musig::AggKey;
use secp256k1::{ecdh, Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::digest::Update;
use sha2::Digest;
use thiserror::Error;

use crate::remote_receive_sm::RemoteReceiveStateMachine;

const KIND: ModuleKind = ModuleKind::from_static_str("lnv2");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMeta {
    pub contract: IncomingContract,
}

/// The final state of an operation receiving a payment over lightning.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalRemoteReceiveOperationState {
    /// The payment has been confirmed.
    Funded,
    /// The payment request has expired.
    Expired,
}

#[derive(Debug)]
pub struct LightningRemoteCommonInit;

impl CommonModuleInit for LightningRemoteCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = LightningClientConfig;

    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

#[derive(Debug, Clone)]
pub struct LightningRemoteClientInit;

impl Default for LightningRemoteClientInit {
    fn default() -> Self {
        Self
    }
}

impl ModuleInit for LightningRemoteClientInit {
    type Common = LightningRemoteCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for LightningRemoteClientInit {
    type Module = LightningClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(LightningClientModule::new(
            *args.federation_id(),
            args.cfg().clone(),
            args.notifier().clone(),
            args.context(),
            args.module_api().clone(),
            args.module_root_secret()
                .clone()
                .to_secp_key(fedimint_core::secp256k1::SECP256K1),
            args.admin_auth().cloned(),
        )
        .await)
    }
}

#[derive(Debug, Clone)]
pub struct LightningClientContext {}

impl Context for LightningClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[derive(Debug)]
pub struct LightningClientModule {
    federation_id: FederationId,
    cfg: LightningClientConfig,
    notifier: ModuleNotifier<LightningClientStateMachines>,
    client_ctx: ClientContext<Self>,
    module_api: DynModuleApi,
    keypair: Keypair,
    #[allow(unused)] // The field is only used by the cli feature
    admin_auth: Option<ApiAuth>,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for LightningClientModule {
    type Init = LightningRemoteClientInit;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = LightningClientContext;
    type States = LightningClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        LightningClientContext {}
    }

    fn input_fee(
        &self,
        amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    fn output_fee(
        &self,
        amount: Amount,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

impl LightningClientModule {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        federation_id: FederationId,
        cfg: LightningClientConfig,
        notifier: ModuleNotifier<LightningClientStateMachines>,
        client_ctx: ClientContext<Self>,
        module_api: DynModuleApi,
        keypair: Keypair,
        admin_auth: Option<ApiAuth>,
    ) -> Self {
        Self {
            federation_id,
            cfg,
            notifier,
            client_ctx,
            module_api,
            keypair,
            admin_auth,
        }
    }

    pub async fn create_offer(
        &self,
        funding_notes: OOBNotes,
        funding_window: Duration,
        contract_info: ContractInfo,
        total_collateral: Amount,
        contract_expiration: u32,
        party_params: PartyParams, // TODO: Calculate this rather than accepting it as an argument.
        expiration: u64,
    ) -> anyhow::Result<DlcOffer> {
        let contract_id = ContractId::new_random();

        let offer = DlcOffer::new(
            contract_id.clone(),
            party_params,
            contract_info,
            total_collateral,
            expiration,
        );

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let existing_entry = dbtx
            .insert_entry(
                &DlcOfferAndMetadataKey(contract_id),
                &DlcOfferAndMetadata {
                    offer: offer.clone(),
                    role: ContractRole::Offerer,
                },
            )
            .await;

        if existing_entry.is_some() {
            return Err(anyhow::anyhow!("Contract ID already exists"));
        }

        dbtx.commit_tx_result().await?;

        Ok(offer)
    }

    pub async fn accept_offer(
        &self,
        offer: DlcOffer,
        funding_notes: OOBNotes,
        party_params: PartyParams, // TODO: Calculate this rather than accepting it as an argument.
    ) -> anyhow::Result<DlcAccept> {
        let accept = DlcAccept::new(offer.contract_id.clone(), party_params, unimplemented!());

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let existing_entry = dbtx
            .insert_entry(
                &DlcOfferAndMetadataKey(offer.contract_id),
                &DlcOfferAndMetadata {
                    offer: offer.clone(),
                    role: ContractRole::Acceptor,
                },
            )
            .await;

        if existing_entry.is_some() {
            return Err(anyhow::anyhow!(
                "Offer with this contract ID already exists"
            ));
        }

        dbtx.insert_entry(&DlcAcceptKey(offer.contract_id), &accept)
            .await;

        if existing_entry.is_some() {
            return Err(anyhow::anyhow!("Contract ID already exists"));
        }

        dbtx.commit_tx_result().await?;

        Ok(accept)
    }

    pub async fn sign(&self, accept: DlcAccept) -> anyhow::Result<DlcSign> {
        let contract_id = accept.contract_id;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let offer_and_metadata = dbtx
            .get_value(&DlcOfferAndMetadataKey(contract_id.clone()))
            .await
            .ok_or_else(|| anyhow::anyhow!("No offer found for contract ID"))?;

        if offer_and_metadata.role != ContractRole::Offerer {
            return Err(anyhow::anyhow!("The acceptor cannot sign"));
        }

        let sign = DlcSign::new(contract_id, unimplemented!(), unimplemented!());

        dbtx.insert_entry(&DlcSignKey(contract_id), &sign).await;

        dbtx.commit_tx_result().await?;

        Ok(sign)
    }

    pub async fn sign_and_publish_funding_tx(&self, sign: DlcSign) -> anyhow::Result<()> {
        let contract_id = sign.contract_id;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let accept: DlcAccept = dbtx
            .get_value(&DlcAcceptKey(contract_id.clone()))
            .await
            .ok_or_else(|| anyhow::anyhow!("No accept found for contract ID"))?;

        let offer_and_metadata = dbtx
            .get_value(&DlcOfferAndMetadataKey(contract_id.clone()))
            .await
            .ok_or_else(|| anyhow::anyhow!("No offer found for contract ID"))?;

        if offer_and_metadata.role != ContractRole::Acceptor {
            return Err(anyhow::anyhow!("The offerer cannot publish"));
        }

        let sign = DlcSign::new(contract_id, unimplemented!(), unimplemented!());

        dbtx.insert_entry(&DlcSignKey(contract_id), &sign).await;

        // TODO: Publish the funding transaction.

        dbtx.commit_tx_result().await?;

        Ok(())
    }
}

fn calculate_payment_preimage(offer: &DlcOffer, accept: &DlcAccept) -> [u8; 32] {
    // Since we hash the offer and accept messages to create the ephemeral pubkey,
    // we double-hash here to ensure that outside viewers cannot correlate the two.
    // The pre-image is double-hashed rather than the ephemeral pubkey because the
    // pre-image needs to be publicly revealed to submit a CET, and we don't want
    // others to be able to correlate the pre-image with the ephemeral pubkey.
    let offer_hash_bytes: [u8; 32] = offer
        .consensus_hash::<sha256::Hash>()
        .hash_again()
        .to_byte_array();
    let accept_hash_bytes: [u8; 32] = accept
        .consensus_hash::<sha256::Hash>()
        .hash_again()
        .to_byte_array();

    xor_32_bytes(&offer_hash_bytes, &accept_hash_bytes)
}

fn calculate_ephemeral_pubkey(offer: &DlcOffer, accept: &DlcAccept) -> PublicKey {
    // Note: We perform a single hash here, but we double-hash these same messages
    // to create the contract pre-image. See `calculate_payment_preimage` for why.
    let offer_hash_bytes: [u8; 32] = offer.consensus_hash::<sha256::Hash>().to_byte_array();
    let accept_hash_bytes: [u8; 32] = accept.consensus_hash::<sha256::Hash>().to_byte_array();

    let secret_bytes = xor_32_bytes(&offer_hash_bytes, &accept_hash_bytes);

    let secret_key = SecretKey::from_slice(&secret_bytes).expect("Always 32 bytes");

    secret_key.public_key(secp256k1::SECP256K1)
}

fn xor_32_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Always 32 bytes")
}

fn get_claim_agg_key(dlc_offer: &DlcOffer, dlc_accept: &DlcAccept) -> AggKey<Normal> {
    let schnorr = schnorr_fun::Schnorr::<
        sha2::Sha256,
        schnorr_fun::nonce::Deterministic<sha2::Sha256>,
    >::default();
    let musig = schnorr_fun::musig::MuSig::new(schnorr);

    // TODO: Simply call `PublicKey.into()` once `schnorr_fun` and
    // `bitcoin` are updated to use the same `secp256k1` version.
    musig.new_agg_key(vec![
        Point::from_bytes(dlc_offer.party_params.claim_pubkey().serialize())
            .expect("Invalid pubkey"),
        Point::from_bytes(dlc_accept.party_params.claim_pubkey().serialize())
            .expect("Invalid pubkey"),
    ])
}

fn get_refund_agg_key(dlc_offer: &DlcOffer, dlc_accept: &DlcAccept) -> AggKey<Normal> {
    let schnorr = schnorr_fun::Schnorr::<
        sha2::Sha256,
        schnorr_fun::nonce::Deterministic<sha2::Sha256>,
    >::default();
    let musig = schnorr_fun::musig::MuSig::new(schnorr);

    // TODO: Simply call `PublicKey.into()` once `schnorr_fun` and `bitcoin`
    // are updated to use the same `secp256k1` version.
    musig.new_agg_key(vec![
        Point::from_bytes(dlc_offer.party_params.refund_pubkey().serialize())
            .expect("Invalid pubkey"),
        Point::from_bytes(dlc_accept.party_params.refund_pubkey().serialize())
            .expect("Invalid pubkey"),
    ])
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum RemoteReceiveError {
    #[error("The gateways fee exceeds the limit")]
    PaymentFeeExceedsLimit,
    #[error("The total fees required to complete this payment exceed its amount")]
    DustAmount,
}

// TODO: Remove this and just use `RemoteReceiveStateMachine`.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    RemoteReceive(RemoteReceiveStateMachine),
}

impl IntoDynInstance for LightningClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for LightningClientStateMachines {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            LightningClientStateMachines::RemoteReceive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    LightningClientStateMachines::RemoteReceive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            LightningClientStateMachines::RemoteReceive(state) => state.operation_id(),
        }
    }
}
