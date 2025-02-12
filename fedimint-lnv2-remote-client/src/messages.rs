use bitcoin::secp256k1::PublicKey;
use ddk_manager::contract::contract_info::ContractInfo;
use ddk_manager::contract::ser::Serializable;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::Amount;
use fedimint_mint_common::Note;
use rand::{thread_rng, Rng};
use schnorr_fun::adaptor::EncryptedSignature;
use schnorr_fun::fun::marker::{Public, Zero};
use schnorr_fun::fun::Scalar;
use schnorr_fun::musig::Nonce;
use secp256k1::schnorr::Signature;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ContractId(pub [u8; 32]);

impl ContractId {
    pub fn new_random() -> Self {
        let mut rng = thread_rng();
        let mut contract_id = [0u8; 32];
        rng.fill(&mut contract_id);
        Self(contract_id)
    }
}

pub struct Sign {
    dlc_sign: DlcSign,
    accept: Accept,
}

pub struct Accept {
    dlc_accept: DlcAccept,
    dlc_offer: DlcOffer,
}

#[derive(Debug, Clone, Encodable, Decodable)]
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

#[derive(Debug, Clone, Encodable, Decodable)]
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

#[derive(Debug, Clone, Encodable, Decodable)]
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
                bincode::deserialize(&mut sig.as_slice())
                    .expect("Always parsed from previously-valid bytes")
            })
            .collect()
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Hash)]
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
    pub input_notes: Vec<Note>,
}

impl PartyParams {
    pub fn new(
        claim_pubkey: PublicKey,
        refund_pubkey: PublicKey,
        public_nonces: Vec<Nonce>,
        input_notes: Vec<Note>,
    ) -> Self {
        Self {
            claim_pubkey: claim_pubkey.serialize(),
            refund_pubkey: refund_pubkey.serialize(),
            public_nonces: public_nonces.iter().map(|nonce| nonce.to_bytes()).collect(),
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
