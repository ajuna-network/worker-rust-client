use codec::{Decode, Encode};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::AccountId32;
use tungstenite::{connect, Message};
use types::{
    Balance, Getter, KeyPair, Request, Rsa3072PublicKey, TrustedCall, TrustedGetter,
    TrustedOperation,
};
use url::Url;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate serde_big_array;

type Hash = sp_core::H256;

use crate::types::{DirectRequestStatus, RpcRequest, RpcResponse, RpcReturnValue};

mod types;
use rand::rngs::OsRng;
use rsa::BigUint;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use sha2::Sha256;

// https://github.com/integritee-network/worker/blob/master/docs/trusted-rpc-interface.md

pub fn trusted_balance_transfer<T: PublicKey>(
    url: &'static str,
    nonce: u32,
    to: AccountId32,
    key_ring: AccountKeyring,
    amount: Balance,
    shard: H256,
    mrenclave: &[u8; 32],
    shielding_pubkey: T,
) -> Result<H256, String> {
    let from: AccountId32 = key_ring.into();
    println!(
        "Creating trusted operation to transfer from {} to {} with nonce {} and amount {}",
        from, to, nonce, amount
    );

    let call = TrustedCall::balance_transfer(from.into(), to, amount);
    let trusted_call_signed =
        call.sign(&KeyPair::Sr25519(key_ring.pair()), nonce, mrenclave, &shard);
    let trusted_operation = TrustedOperation::direct_call(trusted_call_signed);

    let data = trusted_operation.encode();

    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let cyphertext = shielding_pubkey
        .encrypt(&mut rng, padding, &data.as_slice())
        .map_err(|_| "failed to encrypt")?;
    // Create `Request`
    let request = Request { shard, cyphertext };
    // Encode `Request`
    let request_encoded = request.encode();
    // Submit RPC request
    let request = RpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "author_submitAndWatchExtrinsic".to_owned(),
        params: request_encoded.to_vec(),
        id: 1,
    };

    let (mut socket, _) = connect(Url::parse(url).unwrap()).expect("Can't connect");

    let text = serde_json::to_string(&request).unwrap();
    socket.write_message(Message::Text(text)).unwrap();

    match socket
        .read_message()
        .map_err(|_| "failed to read from socket")?
    {
        Message::Text(response) => {
            let response: RpcResponse =
                serde_json::from_str(&response).expect("failed to deserialise");

            match RpcReturnValue::decode(&mut response.result.as_slice()) {
                Ok(return_value) => match return_value.status {
                    DirectRequestStatus::Error => {
                        return match String::decode(&mut return_value.value.as_slice()) {
                            Ok(value) => Err(format!("error returned: {}", value)),
                            Err(_) => Err("failed to decode".into()),
                        }
                    }
                    // Operation would be submitted
                    DirectRequestStatus::TrustedOperationStatus(_) => {
                        return Hash::decode(&mut return_value.value.as_slice())
                            .map_err(|_| "failed to decode hash".into());
                    }
                    _ => return Err("Unknown response".into()),
                },
                Err(_) => return Err("Unable to decode return value".into()),
            }
        }
        _ => return Err("Unknown response".into()),
    }
}

pub fn trusted_getter_nonce<T: PublicKey>(
    url: &'static str,
    key_ring: AccountKeyring,
    shard: H256,
    shielding_pubkey: T,
) -> Result<u32, String> {
    // Create `TrustedGetter`
    let account_id: AccountId32 = key_ring.into();
    let trusted_getter = TrustedGetter::nonce(account_id.clone());
    println!("Creating trusted nonce call with account id {}", account_id);
    // Sign Trusted Getter to give a `SignedTrustedGetter``
    let signed_trusted_getter = trusted_getter.sign(&KeyPair::Sr25519(key_ring.pair()));
    // Wrap with `Getter``
    let getter = Getter::trusted(signed_trusted_getter);
    // Wrap with `TrustedOperation`
    let trusted_operation = TrustedOperation::get(getter);
    // Encode `TrustedOperation` and Encrypt Rsa3072
    let data = trusted_operation.encode();

    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let cyphertext = shielding_pubkey
        .encrypt(&mut rng, padding, &data.as_slice())
        .map_err(|_| "failed to encrypt")?;

    // Create `Request`
    let request = Request { shard, cyphertext };
    // Encode `Request`
    let request_encoded = request.encode();
    // Submit RPC request
    let request = RpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "author_submitAndWatchExtrinsic".to_owned(),
        params: request_encoded.to_vec(),
        id: 1,
    };

    let (mut socket, _) = connect(Url::parse(url).map_err(|_| format!("failed to parse {}", url))?)
        .map_err(|_| format!("failed to connect to {}", url))?;

    let text = serde_json::to_string(&request).expect("failed to serialise");
    socket
        .write_message(Message::Text(text))
        .map_err(|_| "failed to write to socket")?;

    loop {
        match socket
            .read_message()
            .map_err(|_| "failed to read from socket")?
        {
            Message::Text(response) => {
                let response: RpcResponse =
                    serde_json::from_str(&response).expect("failed to deserialise");

                match RpcReturnValue::decode(&mut response.result.as_slice()) {
                    Ok(return_value) => match return_value.status {
                        DirectRequestStatus::Error => {
                            return match String::decode(&mut return_value.value.as_slice()) {
                                Ok(value) => Err(format!("error returned: {}", value)),
                                Err(_) => Err("failed to decode".into()),
                            }
                        }
                        _ => {
                            if !return_value.do_watch {
                                let value =
                                    Option::<Vec<u8>>::decode(&mut return_value.value.as_slice())
                                        .map_err(|_| "failed to decode response")?
                                        .expect("if it decoded to an option");

                                let value = value.as_slice();

                                return Ok(u32::from_le_bytes(
                                    value.try_into().map_err(|_| "this isn't a u32")?,
                                ));
                            }
                        }
                    },
                    Err(_) => return Err("Unable to decode return value".into()),
                }
            }
            _ => return Err("Unknown response".into()),
        }
    }
}

pub fn get_shielding_key(url: &'static str) -> Result<RsaPublicKey, String> {
    let (mut socket, _) = connect(Url::parse(url).unwrap()).expect("Can't connect");

    let request = RpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "author_getShieldingKey".to_owned(),
        params: vec![],
        id: 1,
    };

    let text = serde_json::to_string(&request).expect("failed to serialise");
    socket
        .write_message(Message::Text(text))
        .map_err(|_| "failed to write to socket")?;

    match socket
        .read_message()
        .map_err(|_| "failed to read from socket")?
    {
        Message::Text(response) => {
            let response: RpcResponse =
                serde_json::from_str(&response).expect("failed to deserialise");
            match RpcReturnValue::decode(&mut response.result.as_slice()) {
                Ok(return_value) => match return_value.status {
                    DirectRequestStatus::Error => {
                        return match String::decode(&mut return_value.value.as_slice()) {
                            Ok(value) => Err(format!("error returned: {}", value)),
                            Err(_) => Err("failed to decode".into()),
                        }
                    }
                    DirectRequestStatus::Ok => {
                        let response_message =
                            String::decode(&mut return_value.value.as_slice()).unwrap();
                        let shielding_key: Rsa3072PublicKey =
                            serde_json::from_str(&response_message).unwrap();
                        let n: BigUint = BigUint::from_bytes_le(&shielding_key.n);
                        let e: BigUint = BigUint::from_bytes_le(&shielding_key.e);

                        let shielding_key = rsa::RsaPublicKey::new(n, e).expect("components");

                        Ok(shielding_key)
                    }
                    _ => Err("Unexpected request status".into()),
                },
                Err(_) => return Err("Unable to decode return value".into()),
            }
        }
        _ => Err("Unknown response".into()),
    }
}

pub fn get_rpc_methods(url: &'static str) -> Result<String, String> {
    let (mut socket, _) = connect(Url::parse(url).unwrap()).expect("Can't connect");

    let request = RpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "rpc_methods".to_owned(),
        params: vec![],
        id: 1,
    };

    let text = serde_json::to_string(&request).unwrap();
    socket.write_message(Message::Text(text)).unwrap();

    let response = socket.read_message().unwrap();
    match response {
        Message::Text(response) => Ok(response),
        _ => Err("Invalid response".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MRENCLAVE: &str = "CAG7CwtvDb5AvC3yoxXetYqY97tGSUdywP1U6pgYf1Kh";
    const URL: &str = "ws://20.107.17.237:2000";

    #[test]
    fn test_send_amount() {
        let shielding_key = get_shielding_key(URL).unwrap();
        let mrenclave = bs58::decode(MRENCLAVE).into_vec().unwrap();
        let shard = H256::from_slice(&mrenclave);

        let nonce = trusted_getter_nonce(URL, AccountKeyring::Alice, shard, shielding_key.clone())
            .expect("a nonce value");

        trusted_balance_transfer(
            URL,
            nonce,
            AccountKeyring::Bob.into(),
            AccountKeyring::Alice,
            100,
            shard,
            &mrenclave.try_into().unwrap(),
            shielding_key,
        )
        .expect("balance transfer succeeded");
    }

    #[test]
    fn test_trusted_rpc_methods() {
        println!("rpc methods:\n{}", get_rpc_methods(URL).unwrap());
    }

    #[test]
    fn test_nonce_trusted_getter() {
        let shielding_key = get_shielding_key(URL).unwrap();
        let shard = bs58::decode(MRENCLAVE).into_vec().unwrap();
        let shard = H256::from_slice(&shard);

        trusted_getter_nonce(URL, AccountKeyring::Alice, shard, shielding_key)
            .expect("a nonce value");
    }
}
