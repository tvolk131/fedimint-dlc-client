use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use ddk_manager::contract::contract_info::ContractInfo;
use ddk_manager::contract::ser::Serializable;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, BitcoinHash};
use fedimint_lnv2_common::contracts::{OutgoingContract, PaymentImage};
use fedimint_mint_common::Note;
use rand::{thread_rng, Rng};
use schnorr_fun::adaptor::EncryptedSignature;
use schnorr_fun::binonce::Nonce;
use schnorr_fun::fun::marker::{Public, Zero};
use schnorr_fun::fun::Point;
use schnorr_fun::fun::Scalar;
use secp256k1::schnorr::Signature;

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub struct ContractId(pub [u8; 32]);

impl ContractId {
    pub fn new_random() -> Self {
        let mut rng = thread_rng();
        let mut contract_id = [0u8; 32];
        rng.fill(&mut contract_id);
        Self(contract_id)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub enum ContractRole {
    Offerer = 0,
    Acceptor = 1,
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub struct OfferedContract {
    pub role: ContractRole,
    pub dlc_offer: DlcOffer,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct AcceptedContract {
    pub offered_contract: OfferedContract,
    pub dlc_accept: DlcAccept,
}

impl AcceptedContract {
    pub fn calculate_lnv2_outgoing_contract(&self) -> OutgoingContract {
        OutgoingContract {
            payment_image: PaymentImage::Hash(sha256::Hash::hash(
                &self.calculate_payment_preimage(),
            )),
            amount: self.offered_contract.dlc_offer.total_collateral,
            expiration: self.offered_contract.dlc_offer.expiration,
            claim_pk: self.calculate_claim_agg_key(),
            refund_pk: self.calculate_refund_agg_key(),
            ephemeral_pk: self.calculate_ephemeral_pubkey(),
        }
    }

    pub fn calculate_payment_preimage(&self) -> [u8; 32] {
        // Since we hash the offer and accept messages to create the ephemeral pubkey,
        // we double-hash here to ensure that outside viewers cannot correlate the two.
        // The pre-image is double-hashed rather than the ephemeral pubkey because the
        // pre-image needs to be publicly revealed to submit a CET, and we don't want
        // others to be able to correlate the pre-image with the ephemeral pubkey.
        let offer_hash_bytes: [u8; 32] = self
            .offered_contract
            .dlc_offer
            .consensus_hash::<sha256::Hash>()
            .hash_again()
            .to_byte_array();
        let accept_hash_bytes: [u8; 32] = self
            .dlc_accept
            .consensus_hash::<sha256::Hash>()
            .hash_again()
            .to_byte_array();

        Self::xor_32_bytes(&offer_hash_bytes, &accept_hash_bytes)
    }

    fn calculate_claim_agg_key(&self) -> PublicKey {
        let schnorr = schnorr_fun::Schnorr::<
            sha2::Sha256,
            schnorr_fun::nonce::Deterministic<sha2::Sha256>,
        >::default();
        let musig = schnorr_fun::musig::MuSig::new(schnorr);

        // TODO: Simply call `PublicKey.into()` once `schnorr_fun` and
        // `bitcoin` are updated to use the same `secp256k1` version.
        let agg_key = musig.new_agg_key(vec![
            Point::from_bytes(
                self.offered_contract
                    .dlc_offer
                    .party_params
                    .claim_pubkey()
                    .serialize(),
            )
            .expect("Invalid pubkey"),
            Point::from_bytes(self.dlc_accept.party_params.claim_pubkey().serialize())
                .expect("Invalid pubkey"),
        ]);

        PublicKey::from_slice(&agg_key.agg_public_key().to_bytes()).expect("Always 33 bytes")
    }

    fn calculate_refund_agg_key(&self) -> PublicKey {
        let schnorr = schnorr_fun::Schnorr::<
            sha2::Sha256,
            schnorr_fun::nonce::Deterministic<sha2::Sha256>,
        >::default();
        let musig = schnorr_fun::musig::MuSig::new(schnorr);

        // TODO: Simply call `PublicKey.into()` once `schnorr_fun` and `bitcoin`
        // are updated to use the same `secp256k1` version.
        let agg_key = musig.new_agg_key(vec![
            Point::from_bytes(
                self.offered_contract
                    .dlc_offer
                    .party_params
                    .refund_pubkey()
                    .serialize(),
            )
            .expect("Invalid pubkey"),
            Point::from_bytes(self.dlc_accept.party_params.refund_pubkey().serialize())
                .expect("Invalid pubkey"),
        ]);

        PublicKey::from_slice(&agg_key.agg_public_key().to_bytes()).expect("Always 33 bytes")
    }

    fn calculate_ephemeral_pubkey(&self) -> PublicKey {
        // Note: We perform a single hash here, but we double-hash these same messages
        // to create the contract pre-image. See `calculate_payment_preimage()` for why.
        let offer_hash_bytes: [u8; 32] = self
            .offered_contract
            .dlc_offer
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();
        let accept_hash_bytes: [u8; 32] = self
            .dlc_accept
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let secret_bytes = Self::xor_32_bytes(&offer_hash_bytes, &accept_hash_bytes);

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
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SignedContract {
    pub accepted_contract: AcceptedContract,
    pub dlc_sign: DlcSign,
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub struct DlcOffer {
    /// The contract id. Randomly generated by the offerer.
    pub contract_id: ContractId,

    pub party_params: PartyParams,

    contract_info: Vec<u8>,

    pub total_collateral: Amount,

    pub expiration: u64,
}

impl DlcOffer {
    pub fn new(
        contract_id: ContractId,
        party_params: PartyParams,
        contract_info: ContractInfo,
        total_collateral: Amount,
        expiration: u64,
    ) -> Self {
        Self {
            contract_id,
            party_params,
            contract_info: contract_info.serialize().expect("Always serializable"),
            total_collateral,
            expiration,
        }
    }

    pub fn contract_info(&self) -> ContractInfo {
        ContractInfo::deserialize(&mut self.contract_info.as_slice())
            .expect("Always parsed from previously-valid bytes")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub struct DlcAccept {
    /// The contract id. Randomly generated by the offerer.
    pub contract_id: ContractId,

    pub party_params: PartyParams,

    /// The Musig2 partial signatures to produce adaptor
    /// signatures for the CETs and refund transaction.
    partial_signatures: Vec<[u8; 32]>,
}

impl DlcAccept {
    pub fn new(
        contract_id: ContractId,
        party_params: PartyParams,
        partial_signatures: Vec<Scalar<Public, Zero>>,
    ) -> Self {
        Self {
            contract_id,
            party_params,
            partial_signatures: partial_signatures
                .iter()
                .map(|scalar| scalar.to_bytes())
                .collect(),
        }
    }

    pub fn partial_signatures(&self) -> Vec<Scalar<Public, Zero>> {
        self.partial_signatures
            .iter()
            .map(|bytes| {
                Scalar::from_bytes(*bytes).expect("Always parsed from previously-valid bytes")
            })
            .collect()
    }
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq)]
pub struct DlcSign {
    /// The contract id. Randomly generated by the offerer.
    pub contract_id: ContractId,

    /// The adaptor signatures for the CETs and refund transaction.
    adaptor_signatures: Vec<Vec<u8>>,

    /// Signatures for each of the party's ecash notes across the
    /// funding transaction. The notes were specified in the
    /// `PartyParams` of the `DlcOffer`.
    pub funding_signatures: Vec<Signature>,
}

impl DlcSign {
    pub fn new(
        contract_id: ContractId,
        adaptor_signatures: Vec<EncryptedSignature<Public>>,
        funding_signatures: Vec<Signature>,
    ) -> Self {
        Self {
            contract_id,
            adaptor_signatures: adaptor_signatures
                .into_iter()
                .map(|sig| bincode::serialize(&sig).expect("Always serializable"))
                .collect(),
            funding_signatures,
        }
    }

    pub fn adaptor_signatures(&self) -> Vec<EncryptedSignature<Public>> {
        self.adaptor_signatures
            .iter()
            .map(|sig| {
                bincode::deserialize(sig.as_slice())
                    .expect("Always parsed from previously-valid bytes")
            })
            .collect()
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Hash, PartialEq, Eq)]
pub struct PartyParams {
    /// The public key that is combined with the other party's public key to produce the
    /// combined public key that will be used to create adaptor signatures for CETs.
    /// This is an encoded `PublicKey`.
    claim_pubkey: [u8; 33],

    /// The public key that is combined with the other party's public key to produce the
    /// combined public key that will be used to create an adaptor signature for the
    /// refund transaction.
    /// This is an encoded `PublicKey`.
    refund_pubkey: [u8; 33],

    /// The Musig2 public nonces the counterparty will provide to produce adaptor signatures.
    public_nonces: Vec<[u8; 66]>,

    /// The notes that the offerer party will provide as inputs to fund the contract.
    /// The denomination of each note can be determined by checking the signature of the note
    /// against the federation's public keys for all note denominations until a match is found.
    pub input_notes: Vec<(Amount, Vec<Note>)>,
}

impl PartyParams {
    pub fn new(
        claim_pubkey: PublicKey,
        refund_pubkey: PublicKey,
        public_nonces: &[Nonce],
        input_notes: Vec<(Amount, Vec<Note>)>,
    ) -> Self {
        Self {
            claim_pubkey: claim_pubkey.serialize(),
            refund_pubkey: refund_pubkey.serialize(),
            public_nonces: public_nonces.iter().map(Nonce::to_bytes).collect(),
            input_notes,
        }
    }

    pub fn claim_pubkey(&self) -> PublicKey {
        PublicKey::from_slice(&self.claim_pubkey).expect("Always 32 bytes")
    }

    pub fn refund_pubkey(&self) -> PublicKey {
        PublicKey::from_slice(&self.refund_pubkey).expect("Always 32 bytes")
    }

    pub fn public_nonces(&self) -> Vec<Nonce> {
        self.public_nonces
            .iter()
            .map(|nonce| {
                Nonce::from_bytes(*nonce)
                    .expect("Can never fail, see https://github.com/LLFourn/secp256kfun/pull/206")
            })
            .collect()
    }
}
