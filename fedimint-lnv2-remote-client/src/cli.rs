use std::{ffi, iter};

use bitcoin::hashes::sha256;
use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use fedimint_lnv2_common::ContractId;
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::{Bolt11InvoiceDescription, LightningClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    GetPublicKey,
    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    RemoteReceive {
        claimer_pk: PublicKey,
        #[arg(long)]
        amount: Amount,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the remote receive operation.
    AwaitRemoteReceive {
        #[arg(long)]
        operation_id: OperationId,
    },
    GetClaimableContracts {
        claimer_pk: PublicKey,
        #[arg(long)]
        limit: Option<usize>,
    },
    RemoveClaimedContract {
        #[arg(long)]
        contract_id: sha256::Hash,
    },
    ClaimContract {
        incoming_contract_hex: String,
    },
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
    /// List all vetted gateways.
    List {
        #[arg(long)]
        peer: Option<PeerId>,
    },
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2-remote")).chain(args.iter()));

    let value = match opts {
        Opts::GetPublicKey => json(lightning.get_public_key()),
        Opts::RemoteReceive {
            claimer_pk,
            amount,
            gateway,
        } => json(
            lightning
                .remote_receive(
                    claimer_pk,
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    gateway,
                )
                .await?,
        ),
        Opts::AwaitRemoteReceive { operation_id } => {
            json(lightning.await_remote_receive(operation_id).await?)
        }
        Opts::GetClaimableContracts { claimer_pk, limit } => json(
            lightning
                .get_claimable_contracts(claimer_pk, limit)
                .await
                .into_iter()
                .map(|incoming_contract| {
                    hex::encode(bincode::serialize(&incoming_contract).unwrap())
                })
                .collect::<Vec<_>>(),
        ),
        Opts::RemoveClaimedContract { contract_id } => json(
            lightning
                .remove_claimed_contracts(vec![ContractId(contract_id)])
                .await,
        ),
        Opts::ClaimContract {
            incoming_contract_hex,
        } => json(
            lightning
                .claim_contract(
                    bincode::deserialize(&hex::decode(incoming_contract_hex).unwrap()).unwrap(),
                )
                .await?,
        ),
        Opts::Gateways(gateway_opts) => match gateway_opts {
            GatewaysOpts::List { peer } => match peer {
                Some(peer) => json(lightning.module_api.gateways_from_peer(peer).await?),
                None => json(lightning.module_api.gateways().await?),
            },
        },
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
