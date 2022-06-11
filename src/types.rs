use codec::{Decode, Encode};
use sp_core::{crypto::AccountId32, ed25519, sr25519, Pair, H256};
use sp_runtime::MultiSignature;

pub type Signature = MultiSignature;
pub type AccountId = AccountId32;
pub type BlockHash = H256;
pub type Index = u32;
/// Balance of an account.
pub type Balance = u128;
pub type ShardIdentifier = H256;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedGetter {
    free_balance(AccountId),
    reserved_balance(AccountId),
    nonce(AccountId),
    board(AccountId),
}

impl TrustedGetter {
    pub fn account(&self) -> &AccountId {
        match self {
            TrustedGetter::free_balance(account) => account,
            TrustedGetter::reserved_balance(account) => account,
            TrustedGetter::nonce(account) => account,
            TrustedGetter::board(account) => account,
        }
    }

    pub fn sign(&self, pair: &KeyPair) -> TrustedGetterSigned {
        let signature = pair.sign(self.encode().as_slice());
        TrustedGetterSigned {
            getter: self.clone(),
            signature,
        }
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedGetterSigned {
    pub getter: TrustedGetter,
    pub signature: Signature,
}

// impl TrustedGetterSigned {
// 	pub fn new(getter: TrustedGetter, signature: Signature) -> Self {
// 		TrustedGetterSigned { getter, signature }
// 	}

// 	pub fn verify_signature(&self) -> bool {
// 		self.signature.verify(self.getter.encode().as_slice(), self.getter.account())
// 	}
// }

use serde_derive::*;
big_array! { BigArray; }

#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Rsa3072PublicKey {
    #[serde(with = "BigArray")]
    pub n: [u8; 384],
    pub e: [u8; 4],
}

#[derive(Clone, Encode, Decode, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<String>,
    pub id: i32,
}

#[derive(Clone, Encode, Decode, Debug, Serialize, Deserialize)]
// Todo: result should not be Vec<u8>, but `T: Serialize`
pub struct RpcResponse {
    pub jsonrpc: String,
    pub result: String, // encoded RpcReturnValue
    pub id: u32,
}

#[derive(Clone)]
pub enum KeyPair {
    Sr25519(sr25519::Pair),
    Ed25519(ed25519::Pair),
}

impl KeyPair {
    pub fn sign(&self, payload: &[u8]) -> Signature {
        match self {
            Self::Sr25519(pair) => pair.sign(payload).into(),
            Self::Ed25519(pair) => pair.sign(payload).into(),
        }
    }
}

impl From<ed25519::Pair> for KeyPair {
    fn from(x: ed25519::Pair) -> Self {
        KeyPair::Ed25519(x)
    }
}

impl From<sr25519::Pair> for KeyPair {
    fn from(x: sr25519::Pair) -> Self {
        KeyPair::Sr25519(x)
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Getter {
    public(PublicGetter),
    trusted(TrustedGetterSigned),
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PublicGetter {
    some_value,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedOperation {
    indirect_call(TrustedCallSigned),
    direct_call(TrustedCallSigned),
    get(Getter),
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedCallSigned {
    pub call: TrustedCall,
    pub nonce: Index,
    pub signature: Signature,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedCall {
    balance_set_balance(AccountId, AccountId, Balance, Balance),
    balance_transfer(AccountId, AccountId, Balance),
    balance_unshield(AccountId, AccountId, Balance, ShardIdentifier), // (AccountIncognito, BeneficiaryPublicAccount, Amount, Shard)
    balance_shield(AccountId, AccountId, Balance), // (Root, AccountIncognito, Amount)
    new_game(AccountId, AccountId, AccountId),
    connectfour_play_turn(AccountId, u8),
}

impl TrustedCall {
    pub fn sign(
        &self,
        pair: &KeyPair,
        nonce: Index,
        mrenclave: &[u8; 32],
        shard: &ShardIdentifier,
    ) -> TrustedCallSigned {
        let mut payload = self.encode();
        payload.append(&mut nonce.encode());
        payload.append(&mut mrenclave.encode());
        payload.append(&mut shard.encode());

        TrustedCallSigned {
            call: self.clone(),
            nonce,
            signature: pair.sign(payload.as_slice()),
        }
    }
}

// Note in the pallet teerex this is a struct. But for the codec this does not matter.
#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub shard: ShardIdentifier,
    pub cyphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum DirectRequestStatus {
    /// Direct request was successfully executed
    Ok,
    /// Trusted Call Status
    TrustedOperationStatus(TrustedOperationStatus),
    /// Direct request could not be executed
    Error,
}

#[derive(Encode, Decode, Debug)]
pub struct RpcReturnValue {
    pub value: Vec<u8>,
    pub do_watch: bool,
    pub status: DirectRequestStatus,
    //pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum TrustedOperationStatus {
    /// TrustedOperation is submitted to the top pool.
    Submitted,
    /// TrustedOperation is part of the future queue.
    Future,
    /// TrustedOperation is part of the ready queue.
    Ready,
    /// The operation has been broadcast to the given peers.
    Broadcast,
    /// TrustedOperation has been included in block with given hash.
    InSidechainBlock(BlockHash),
    /// The block this operation was included in has been retracted.
    Retracted,
    /// Maximum number of finality watchers has been reached,
    /// old watchers are being removed.
    FinalityTimeout,
    /// TrustedOperation has been finalized by a finality-gadget, e.g GRANDPA
    Finalized,
    /// TrustedOperation has been replaced in the pool, by another operation
    /// that provides the same tags. (e.g. same (sender, nonce)).
    Usurped,
    /// TrustedOperation has been dropped from the pool because of the limit.
    Dropped,
    /// TrustedOperation is no longer valid in the current state.
    Invalid,
}

impl RpcReturnValue {
    pub fn new(val: Vec<u8>, watch: bool, status: DirectRequestStatus) -> Self {
        Self {
            value: val,
            do_watch: watch,
            status,
            //signature: sign,
        }
    }

    pub fn from_error_message(error_msg: &str) -> Self {
        RpcReturnValue {
            value: error_msg.encode(),
            do_watch: false,
            status: DirectRequestStatus::Error,
        }
    }
}
