use devimint::cmd;
use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::Amount;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_remote_client::FinalRemoteReceiveOperationState;
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fed = dev_fed.fed().await?;

        fed.pegin_gateways(
            1_000_000,
            vec![
                dev_fed.gw_cln().await.unwrap(),
                dev_fed.gw_lnd().await.unwrap(),
                dev_fed.gw_ldk().await.unwrap().as_ref().unwrap(),
            ],
        )
        .await?;

        let ldk_gw_addr = dev_fed.gw_cln().await.as_ref().unwrap().addr.clone();

        info!("Testing happy path");
        test_happy_path(
            &dev_fed,
            fed.new_joined_client("client0").await?,
            fed.new_joined_client("client1").await?,
            &ldk_gw_addr,
        )
        .await?;

        info!("Testing syncing many payments");
        test_syncing_many_payments(
            &dev_fed,
            fed.new_joined_client("client2").await?,
            fed.new_joined_client("client3").await?,
            &ldk_gw_addr,
        )
        .await?;

        info!("Testing idempotency");
        test_idempotency(
            &dev_fed,
            fed.new_joined_client("client4").await?,
            fed.new_joined_client("client5").await?,
            &ldk_gw_addr,
        )
        .await?;

        info!("Successfully completed fedimint-lnv2-remote test");

        Ok(())
    })
    .await
}

async fn test_happy_path(
    dev_fed: &DevJitFed,
    receiver_client: Client,
    claimer_client: Client,
    gw_addr: &str,
) -> anyhow::Result<()> {
    let claimer_pk = get_public_key(&claimer_client).await?;

    let (invoice, operation_id) = remote_receive(
        &receiver_client,
        claimer_pk,
        &Amount::from_msats(1_000_000),
        gw_addr,
    )
    .await?;

    let claimable_contracts = get_claimable_contracts(&receiver_client, claimer_pk, None).await?;
    assert!(claimable_contracts.is_empty());

    dev_fed
        .lnd()
        .await
        .unwrap()
        .pay_bolt11_invoice(invoice.to_string())
        .await
        .unwrap();

    await_remote_receive(&receiver_client, operation_id).await?;

    let claimable_contracts = get_claimable_contracts(&receiver_client, claimer_pk, None).await?;
    assert_eq!(claimable_contracts.len(), 1);
    let incoming_contract_hex = claimable_contracts[0].clone();

    claim_contract(&claimer_client, &incoming_contract_hex).await?;

    let incoming_contract: IncomingContract =
        bincode::deserialize(&hex::decode(incoming_contract_hex).unwrap()).unwrap();

    remove_claimed_contract(&receiver_client, incoming_contract.contract_id()).await?;

    let claimable_contracts = get_claimable_contracts(&receiver_client, claimer_pk, None).await?;
    assert!(claimable_contracts.is_empty());

    assert_eq!(claimer_client.balance().await.unwrap(), 943_055);

    Ok(())
}

async fn test_syncing_many_payments(
    dev_fed: &DevJitFed,
    receiver_client: Client,
    claimer_client: Client,
    gw_addr: &str,
) -> anyhow::Result<()> {
    const INVOICES_COUNT: usize = 20;

    let claimer_pk = get_public_key(&claimer_client).await?;

    let mut invoices = Vec::new();
    for _ in 0..INVOICES_COUNT {
        invoices.push(
            remote_receive(
                &receiver_client,
                claimer_pk,
                &Amount::from_msats(1_000_000),
                gw_addr,
            )
            .await?,
        );
    }

    assert!(get_claimable_contracts(&receiver_client, claimer_pk, None)
        .await?
        .is_empty());
    assert!(
        get_claimable_contracts(&receiver_client, claimer_pk, Some(0))
            .await?
            .is_empty()
    );
    assert!(
        get_claimable_contracts(&receiver_client, claimer_pk, Some(10))
            .await?
            .is_empty()
    );

    for (invoice, _operation_id) in &invoices {
        dev_fed
            .lnd()
            .await
            .unwrap()
            .pay_bolt11_invoice(invoice.to_string())
            .await
            .unwrap();
    }

    for (_invoice, operation_id) in invoices {
        await_remote_receive(&receiver_client, operation_id).await?;
    }

    assert_eq!(
        get_claimable_contracts(&receiver_client, claimer_pk, Some(INVOICES_COUNT - 1))
            .await?
            .len(),
        INVOICES_COUNT - 1
    );
    assert_eq!(
        get_claimable_contracts(&receiver_client, claimer_pk, Some(INVOICES_COUNT + 1))
            .await?
            .len(),
        INVOICES_COUNT
    );

    let claimable_contracts = get_claimable_contracts(&receiver_client, claimer_pk, None).await?;
    assert_eq!(claimable_contracts.len(), INVOICES_COUNT);

    for i in 0..INVOICES_COUNT {
        claim_contract(&claimer_client, &claimable_contracts[i]).await?;

        let incoming_contract: IncomingContract =
            bincode::deserialize(&hex::decode(&claimable_contracts[i]).unwrap()).unwrap();

        // TODO: Test removing contracts in bulk. This needs to be piped through the
        // CLI.
        remove_claimed_contract(&receiver_client, incoming_contract.contract_id()).await?;
    }

    let claimable_contracts = get_claimable_contracts(&receiver_client, claimer_pk, None).await?;
    assert!(claimable_contracts.is_empty());

    assert_eq!(
        claimer_client.balance().await.unwrap(),
        943_055 * INVOICES_COUNT as u64
    );

    Ok(())
}

// TODO: Test idempotency of entire client API.
async fn test_idempotency(
    dev_fed: &DevJitFed,
    receiver_client: Client,
    claimer_client: Client,
    gw_addr: &str,
) -> anyhow::Result<()> {
    let claimer_pk = get_public_key(&claimer_client).await?;

    let (invoice, operation_id) = remote_receive(
        &receiver_client,
        claimer_pk,
        &Amount::from_msats(1_000_000),
        gw_addr,
    )
    .await?;

    dev_fed
        .lnd()
        .await
        .unwrap()
        .pay_bolt11_invoice(invoice.to_string())
        .await
        .unwrap();

    for _ in 0..20 {
        await_remote_receive(&receiver_client, operation_id).await?;
    }

    let claimable_contracts = get_claimable_contracts(&receiver_client, claimer_pk, None).await?;
    assert_eq!(claimable_contracts.len(), 1);
    let incoming_contract_hex = claimable_contracts[0].clone();

    for _ in 0..20 {
        claim_contract(&claimer_client, &incoming_contract_hex).await?;
    }

    assert_eq!(claimer_client.balance().await.unwrap(), 943_055);

    Ok(())
}

async fn get_public_key(client: &Client) -> anyhow::Result<PublicKey> {
    Ok(serde_json::from_value(
        cmd!(client, "module", "lnv2", "get-public-key")
            .out_json()
            .await?,
    )?)
}

async fn remote_receive(
    receiver_client: &Client,
    claimer_pk: PublicKey,
    amount: &Amount,
    gateway: &str,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    let mut json_result = cmd!(
        receiver_client,
        "module",
        "lnv2",
        "remote-receive",
        claimer_pk,
        "--amount",
        amount.to_string(),
        "--gateway",
        gateway
    )
    .out_json()
    .await?;

    let json_array = json_result.as_array_mut().unwrap();

    assert_eq!(json_array.len(), 2);

    let operation_id: OperationId = json_array.pop().unwrap().as_str().unwrap().parse().unwrap();
    let invoice: Bolt11Invoice = json_array.pop().unwrap().as_str().unwrap().parse().unwrap();

    Ok((invoice, operation_id))
}

async fn await_remote_receive(client: &Client, operation_id: OperationId) -> anyhow::Result<()> {
    assert_eq!(
        cmd!(
            client,
            "module",
            "lnv2",
            "await-remote-receive",
            "--operation-id",
            serde_json::to_string(&operation_id)?.substring(1, 65)
        )
        .out_json()
        .await?,
        serde_json::to_value(FinalRemoteReceiveOperationState::Funded)
            .expect("JSON serialization failed"),
    );

    Ok(())
}

async fn get_claimable_contracts(
    client: &Client,
    claimer_pk: PublicKey,
    limit_or: Option<usize>,
) -> anyhow::Result<Vec<String>> {
    let json_value = if let Some(limit) = limit_or {
        cmd!(
            client,
            "module",
            "lnv2",
            "get-claimable-contracts",
            claimer_pk,
            "--limit",
            limit
        )
        .out_json()
        .await?
    } else {
        cmd!(
            client,
            "module",
            "lnv2",
            "get-claimable-contracts",
            claimer_pk
        )
        .out_json()
        .await?
    };

    Ok(serde_json::from_value(json_value)?)
}

async fn remove_claimed_contract(client: &Client, contract_id: ContractId) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "module",
        "lnv2",
        "remove-claimed-contract",
        "--contract-id",
        contract_id.0
    )
    .run()
    .await?)
}

async fn claim_contract(client: &Client, incoming_contract_hex: &str) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "module",
        "lnv2",
        "claim-contract",
        incoming_contract_hex
    )
    .run()
    .await?)
}
