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

use std::collections::BTreeMap;
use std::hash::Hash;
use std::time::Duration;

use bitcoin::secp256k1::Keypair;
use db::{insert_accepted_contract, insert_offered_contract, insert_signed_contract};
use ddk_manager::contract::contract_info::ContractInfo;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule};
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleConsensusVersion, ModuleInit,
    MultiApiVersion,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::{LightningModuleTypes, MODULE_CONSENSUS_VERSION};
use fedimint_mint_client::OOBNotes;
use fedimint_mint_common::Note;
use messages::{
    ContractId, ContractRole, DlcAccept, DlcOffer, DlcSign, OfferedContract, PartyParams,
};
use schnorr_fun::binonce::{NonceKeyPair, SecretNonce};
use schnorr_fun::fun::Scalar;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
        // TODO: Implement this.
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
        ))
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
    notifier: ModuleNotifier<DlcClientStateMachines>,
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
    type States = DlcClientStateMachines;

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
    fn new(
        federation_id: FederationId,
        cfg: LightningClientConfig,
        notifier: ModuleNotifier<DlcClientStateMachines>,
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
        contract_info: ContractInfo,
        total_collateral: Amount,
        expiration: u64,
    ) -> anyhow::Result<DlcOffer> {
        let contract_id = ContractId::new_random();

        let nonces = self.generate_nonces(&contract_id, &contract_info, &total_collateral);

        let public_nonces = nonces
            .iter()
            .map(|nonce| nonce.public())
            .collect::<Vec<_>>();

        let party_params = PartyParams::new(
            self.generate_claim_keypair(&contract_id).public_key(),
            self.generate_refund_keypair(&contract_id).public_key(),
            &public_nonces,
            oob_notes_to_tiered_nonces(funding_notes),
        );

        let dlc_offer = DlcOffer::new(
            contract_id.clone(),
            party_params,
            contract_info,
            total_collateral,
            expiration,
        );

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        insert_offered_contract(
            &mut dbtx.to_ref_nc(),
            OfferedContract {
                role: ContractRole::Offerer,
                dlc_offer: dlc_offer.clone(),
            },
        )
        .await?;

        dbtx.commit_tx_result().await?;

        Ok(dlc_offer)
    }

    pub async fn accept_offer(
        &self,
        dlc_offer: DlcOffer,
        funding_notes: OOBNotes,
    ) -> anyhow::Result<DlcAccept> {
        let contract_info = dlc_offer.contract_info();
        let contract_id = dlc_offer.contract_id;
        let total_collateral = dlc_offer.total_collateral;

        let nonces = self.generate_nonces(&contract_id, &contract_info, &total_collateral);

        let public_nonces = nonces
            .iter()
            .map(|nonce| nonce.public())
            .collect::<Vec<_>>();

        let party_params = PartyParams::new(
            self.generate_claim_keypair(&contract_id).public_key(),
            self.generate_refund_keypair(&contract_id).public_key(),
            &public_nonces,
            oob_notes_to_tiered_nonces(funding_notes),
        );

        let dlc_accept = DlcAccept::new(contract_id.clone(), party_params, unimplemented!());

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        insert_offered_contract(
            &mut dbtx.to_ref_nc(),
            OfferedContract {
                role: ContractRole::Acceptor,
                dlc_offer,
            },
        )
        .await?;

        insert_accepted_contract(&mut dbtx.to_ref_nc(), dlc_accept).await?;

        dbtx.commit_tx_result().await?;

        Ok(dlc_accept)
    }

    pub async fn sign(&self, dlc_accept: DlcAccept) -> anyhow::Result<DlcSign> {
        let dlc_sign = DlcSign::new(dlc_accept.contract_id, unimplemented!(), unimplemented!());

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        insert_accepted_contract(&mut dbtx.to_ref_nc(), dlc_accept).await?;

        insert_signed_contract(&mut dbtx.to_ref_nc(), dlc_sign).await?;

        dbtx.commit_tx_result().await?;

        Ok(dlc_sign)
    }

    pub async fn finalize_and_publish_funding_tx(&self, dlc_sign: DlcSign) -> anyhow::Result<()> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let accepted_contract = insert_signed_contract(&mut dbtx.to_ref_nc(), dlc_sign).await?;

        if accepted_contract.offered_contract.role != ContractRole::Acceptor {
            return Err(anyhow::anyhow!(
                "The offerer cannot publish, only the acceptor"
            ));
        }

        // TODO: Start state machine that publishes the funding transaction.

        dbtx.commit_tx_result().await?;

        Ok(())
    }

    fn generate_claim_keypair(&self, contract_id: &ContractId) -> Keypair {
        let scalar = secp256k1::Scalar::from_be_bytes(contract_id.0).unwrap();
        self.keypair
            .add_xonly_tweak(&secp256k1::SECP256K1, &scalar)
            .unwrap()
            .add_xonly_tweak(
                &secp256k1::SECP256K1,
                &secp256k1::Scalar::from_be_bytes([0u8; 32]).unwrap(),
            )
            .unwrap()
    }

    fn generate_refund_keypair(&self, contract_id: &ContractId) -> Keypair {
        let scalar = secp256k1::Scalar::from_be_bytes(contract_id.0).unwrap();
        self.keypair
            .add_xonly_tweak(&secp256k1::SECP256K1, &scalar)
            .unwrap()
            .add_xonly_tweak(
                &secp256k1::SECP256K1,
                &secp256k1::Scalar::from_be_bytes([1u8; 32]).unwrap(),
            )
            .unwrap()
    }

    fn generate_nonces(
        &self,
        contract_id: &ContractId,
        contract_info: &ContractInfo,
        total_collateral: &Amount,
    ) -> Vec<NonceKeyPair> {
        let secret_key_scalar = Scalar::from_bytes(self.keypair.secret_bytes())
            .unwrap()
            .non_zero()
            .unwrap();

        let nonce_gen = schnorr_fun::nonce::Deterministic::<sha2::Sha256>::default();

        let payouts = contract_info.get_payouts(total_collateral.msats).unwrap();

        payouts
            .into_iter()
            .enumerate()
            .map(|(payout_index, _payout)| {
                SecretNonce([
                    schnorr_fun::fun::derive_nonce!(
                        nonce_gen => nonce_gen,
                        secret => secret_key_scalar,
                        public => [contract_id.0, payout_index.to_le_bytes(), [0]]
                    ),
                    schnorr_fun::fun::derive_nonce!(
                        nonce_gen => nonce_gen,
                        secret => secret_key_scalar,
                        public => [contract_id.0, payout_index.to_le_bytes(), [1]]
                    ),
                ])
                .into_keypair()
            })
            .collect()
    }
}

fn oob_notes_to_tiered_nonces(oob_notes: OOBNotes) -> Vec<(Amount, Vec<Note>)> {
    oob_notes
        .notes()
        .iter()
        .map(|note_tier| {
            (
                note_tier.0,
                note_tier
                    .1
                    .into_iter()
                    .map(|note| Note {
                        nonce: note.nonce(),
                        signature: note.signature,
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum RemoteReceiveError {
    #[error("The gateways fee exceeds the limit")]
    PaymentFeeExceedsLimit,
    #[error("The total fees required to complete this payment exceed its amount")]
    DustAmount,
}

// TODO: Add some state machine variants here.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DlcClientStateMachines {}

impl IntoDynInstance for DlcClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for DlcClientStateMachines {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        unimplemented!()
    }

    fn operation_id(&self) -> OperationId {
        unimplemented!()
    }
}
