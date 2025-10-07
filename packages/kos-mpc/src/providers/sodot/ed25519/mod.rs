use crate::providers::sodot::vertex;
use kos::chains::{klv::KLV, Chain};
use kos_codec::{encode_for_broadcast, encode_for_signing, KosCodedAccount};
use reqwest::{self};
use sodot_mpc::{Ed25519, KeygenId, SecretShare};
use std::num::NonZeroU16;
use tokio;

const N: u16 = 2;
const T: u16 = 2;
const DEMO_HOST_URL: &str = "demo.sodot.dev";

fn get_api_key() -> String {
    std::env::var("RELAY_API_KEY").unwrap()
}

async fn sodot_example_keygen_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    let ed25519 = Ed25519::new(DEMO_HOST_URL.to_string());

    // Your server side creates a room for 2 parties using its API_KEY
    // Creating a room uuid should always happen on the server side using your API_KEY, so that the API_KEY is never exposed to the client side
    let keygen_room_uuid = ed25519
        .create_room(NonZeroU16::new(N).unwrap(), &get_api_key())
        .await?;

    // All parties call init_keygen to get (KeygenId, KeygenPrivateKey) as result
    // The KeygenId is the public part that you should pass to all other parties, the KeygenPrivateKey is the private state you should keep until the actual keygen completes.
    let (keygen_id, keygen_private_key) = ed25519.init_keygen()?;

    // generate key
    let serverKeygen: vertex::CreateResponseBody = vertex::generate_key("ed25519").await?;
    println!("Server Keygen: {:?}", serverKeygen);

    // All parties receive the keygenIds from all other parties
    let keygen_ids = [
        KeygenId::new(serverKeygen.keygen_id), // generated from ed25519/create
    ];

    let server_join_handle = vertex::server_join_room(
        "ed25519",
        &keygen_room_uuid.as_str(),
        serverKeygen.key_id,
        vec![keygen_id.as_str().to_string()],
    );

    let keygen_handler = ed25519.keygen(
        &keygen_room_uuid,
        N.try_into().expect("N is a valid NonZeroU16"),
        T.try_into().expect("T is a valid NonZeroU16"),
        &keygen_private_key,
        &keygen_ids,
    );

    // Await the server join room task and keygen task concurrently
    let (keygen_result, server_join_result) = tokio::join!(keygen_handler, server_join_handle);

    println!("Server Join Room Response: {:?}", server_join_result);

    let (public_key, secret_share) = keygen_result.unwrap();

    let serialized_public_key = public_key.as_bytes();
    println!(
        "Serialized Public Key: {}",
        hex::encode(serialized_public_key)
    );

    let serialized_secret_share = secret_share.as_str();
    println!("Serialized Secret Share: {}", serialized_secret_share);

    Ok(())
}

async fn sodot_example_derive_address_ed25519(
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let klv = KLV {};
    let address = klv.get_address(hex::decode(public_key)?).unwrap();
    println!("KLV Address: {:?}", address);
    Ok(())
}

async fn keygen_ed25519() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ed25519 = Ed25519::new(DEMO_HOST_URL.to_string());

    // Your server side creates a room for 2 parties using its API_KEY
    // Creating a room uuid should always happen on the server side using your API_KEY, so that the API_KEY is never exposed to the client side
    let keygen_room_uuid = ed25519
        .create_room(NonZeroU16::new(N).unwrap(), &get_api_key())
        .await?;

    // All parties call init_keygen to get (KeygenId, KeygenPrivateKey) as result
    // The KeygenId is the public part that you should pass to all other parties, the KeygenPrivateKey is the private state you should keep until the actual keygen completes.
    let (keygen_id, keygen_private_key) = ed25519.init_keygen()?;

    // generate key
    let serverKeygen: vertex::CreateResponseBody = vertex::generate_key("ed25519").await?;
    println!("Server Keygen: {:?}", serverKeygen);

    // All parties receive the keygenIds from all other parties
    let keygen_ids = [
        KeygenId::new(serverKeygen.keygen_id), // generated from ed25519/create
    ];

    let server_join_handle = vertex::server_join_room(
        "ed25519",
        &keygen_room_uuid.as_str(),
        serverKeygen.key_id,
        vec![keygen_id.as_str().to_string()],
    );

    let keygen_handler = ed25519.keygen(
        &keygen_room_uuid,
        N.try_into().expect("N is a valid NonZeroU16"),
        T.try_into().expect("T is a valid NonZeroU16"),
        &keygen_private_key,
        &keygen_ids,
    );

    // Await the server join room task and keygen task concurrently
    let (keygen_result, server_join_result) = tokio::join!(keygen_handler, server_join_handle);

    println!("Server Join Room Response: {:?}", server_join_result);

    let (public_key, secret_share) = keygen_result.unwrap();

    let serialized_public_key = public_key.as_bytes();
    println!(
        "Serialized Public Key: {}",
        hex::encode(serialized_public_key)
    );

    let serialized_secret_share = secret_share.as_str();
    println!("Serialized Secret Share: {}", serialized_secret_share);

    let serialized_secret_share_bytes = hex::decode(serialized_secret_share)?;

    Ok(serialized_secret_share_bytes)
}

pub async fn derive_public_key_ed25519(
    serialized_secret_share: &str,
    derivation_path: &[u32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ed25519 = Ed25519::new(DEMO_HOST_URL.to_string());

    // Restore the secret share from the serialized string
    let restored_share = SecretShare::<Ed25519>::from(serialized_secret_share.to_string());

    // Get the public key for the derivation path
    let derived_pubkey = ed25519.derive_pubkey(&restored_share, &derivation_path)?;
    let compressed_pubkey = hex::encode(derived_pubkey.as_bytes());

    println!("Compressed Derived Public Key: {:?}", compressed_pubkey);

    Ok(derived_pubkey.as_bytes().to_vec())
}

pub async fn sign_ed25519(
    secret_share: &str,
    key_id: &str,
    derivation_path: &[u32],
    hash: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ed25519 = Ed25519::new(DEMO_HOST_URL.to_string());

    let signing_room_uuid = ed25519
        .create_room(NonZeroU16::new(N).unwrap(), &get_api_key())
        .await?;

    let secret_share = SecretShare::<Ed25519>::from(secret_share.to_string());

    let hash_hex = hex::encode(hash);

    let server_sign_handler = vertex::server_join_sign_message_room(
        "ed25519",
        &signing_room_uuid.as_str(),
        key_id.to_string(),
        &derivation_path,
        &hash_hex,
    );

    let signature_handle = ed25519.sign(&signing_room_uuid, &secret_share, &hash, &derivation_path);

    let (signature_result, _) = tokio::join!(signature_handle, server_sign_handler);

    let signature = signature_result.unwrap();

    Ok(signature.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    use kos::chains::{ada::ADA, apt::APT, icp::ICP, sol::SOL, sui::SUI, xlm::XLM, ChainError};

    fn get_ecdsa_secret_share() -> String {
        std::env::var("ECDSA_SECRET_SHARE").unwrap()
    }

    fn get_ecdsa_key_id() -> String {
        std::env::var("ECDSA_KEY_ID").unwrap()
    }

    fn get_ed25519_secret_share() -> String {
        std::env::var("ED25519_SECRET_SHARE").unwrap()
    }

    fn get_ed25519_key_id() -> String {
        std::env::var("ED25519_KEY_ID").unwrap()
    }

    fn parse_derivation_path(path: String) -> Result<Vec<u32>, ChainError> {
        // Remove the 'm/' prefix if present
        let path = path.strip_prefix("m/").unwrap_or(&path);

        let mut components = Vec::new();

        for part in path.split('/') {
            if part.is_empty() {
                continue;
            }

            // Remove the hardened indicator (') if present
            let cleaned_part = part.strip_suffix('\'').unwrap_or(part);

            // Parse the number
            match cleaned_part.parse::<u32>() {
                Ok(num) => components.push(num),
                Err(_) => return Err(ChainError::InvalidPublicKey),
            }
        }

        Ok(components)
    }

    #[tokio::test]
    async fn test_sodot_example_keygen_ed25519() {
        sodot_example_keygen_ed25519().await.unwrap();
    }

    #[tokio::test]
    async fn test_sodot_derive_public_key_ed25519() {
        // KLV, ADA, APT, ICP, SOL, SUI, XLM

        let index = 1;

        let klv = KLV {};
        let path = klv.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();

        let klv_address = klv.get_address(pub_key.clone()).unwrap();
        println!("KLV Address: {:?}", klv_address);

        let ada = ADA {};
        let path = ada.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();

        let ada_address = ada.get_address(pub_key.clone()).unwrap();
        println!("ADA Address: {:?}", ada_address);

        let apt = APT {};
        let path = apt.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();

        let apt_address = apt.get_address(pub_key.clone()).unwrap();
        println!("APT Address: {:?}", apt_address);

        let icp = ICP::new(kos::KeyType::ED25519);
        let path = icp.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();

        let icp_address = icp.get_address(pub_key.clone()).unwrap();
        println!("ICP Address: {:?}", icp_address);

        let sol = SOL {};
        let path = sol.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();

        let sol_address = sol.get_address(pub_key.clone()).unwrap();
        println!("SOL Address: {:?}", sol_address);

        let sui = SUI {};
        let path = sui.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();
        let sui_address = sui.get_address(pub_key.clone()).unwrap();
        println!("SUI Address: {:?}", sui_address);

        let xlm = XLM {};
        let path = xlm.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &derivation_path)
            .await
            .unwrap();

        let xlm_address = xlm.get_address(pub_key.clone()).unwrap();
        println!("XLM Address: {:?}", xlm_address);
    }

    #[tokio::test]
    async fn test_sodot_derive_address_ed25519() {
        let pub_key = derive_public_key_ed25519(&get_ed25519_secret_share(), &[44, 690, 0, 0, 0])
            .await
            .unwrap();

        assert_eq!(
            hex::encode(pub_key),
            "f6e202fc4447c27aa125ad383386caf67902efd4bfdede5d7e7237c07ca7c0b6"
        );
    }
}
