use crate::providers::sodot::vertex;
use sodot_mpc::{ecdsa::MessageHash, Ecdsa, KeygenId, SecretShare};
use std::num::NonZeroU16;
use tokio;

const N: u16 = 2;
const T: u16 = 2;
const DEMO_HOST_URL: &str = "demo.sodot.dev";

fn get_api_key() -> String {
    std::env::var("RELAY_API_KEY").unwrap()
}

async fn keygen_ecdsa() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ecdsa = Ecdsa::new(DEMO_HOST_URL.to_string());

    // Your server side creates a room for 2 parties using its API_KEY
    // Creating a room uuid should always happen on the server side using your API_KEY, so that the API_KEY is never exposed to the client side
    let keygen_room_uuid = ecdsa
        .create_room(NonZeroU16::new(N).unwrap(), &get_api_key())
        .await?;

    // All parties call init_keygen to get (KeygenId, KeygenPrivateKey) as result
    // The KeygenId is the public part that you should pass to all other parties, the KeygenPrivateKey is the private state you should keep until the actual keygen completes.
    let (keygen_id, keygen_private_key) = ecdsa.init_keygen()?;

    // generate key
    let serverKeygen: vertex::CreateResponseBody = vertex::generate_key("ecdsa").await?;
    println!("Server Keygen: {:?}", serverKeygen);

    // All parties receive the keygenIds from all other parties
    let keygen_ids = [
        KeygenId::new(serverKeygen.keygen_id), // generated from ecdsa/create
    ];

    let server_join_handle = vertex::server_join_room(
        "ecdsa",
        &keygen_room_uuid.as_str(),
        serverKeygen.key_id,
        vec![keygen_id.as_str().to_string()],
    );

    let keygen_handler = ecdsa.keygen(
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

    let serialized_public_key = public_key.compressed();
    println!(
        "Serialized Public Key: {}",
        hex::encode(serialized_public_key)
    );

    let serialized_secret_share = secret_share.as_str();
    println!("Serialized Secret Share: {}", serialized_secret_share);

    let serialized_secret_share_bytes = hex::decode(serialized_secret_share)?;

    Ok(serialized_secret_share_bytes)
}

pub async fn derive_public_key_ecdsa(
    serialized_secret_share: &str,
    derivation_path: &[u32],
) -> Result<sodot_mpc::PublicKey<Ecdsa, 65>, Box<dyn std::error::Error>> {
    let ecdsa = Ecdsa::new(DEMO_HOST_URL.to_string());

    // Restore the secret share from the serialized string
    let restored_share = SecretShare::<Ecdsa>::from(serialized_secret_share.to_string());

    // Get the public key for the derivation path
    let derived_pubkey: sodot_mpc::PublicKey<Ecdsa, 65> =
        ecdsa.derive_pubkey(&restored_share, &derivation_path)?;
    let uncompressed_pubkey = hex::encode(derived_pubkey.uncompressed());
    let compressed_pubkey = hex::encode(derived_pubkey.compressed());

    println!("Uncompressed Derived Public Key: {:?}", uncompressed_pubkey);
    println!("Compressed Derived Public Key: {:?}", compressed_pubkey);

    Ok(derived_pubkey)
}

pub async fn sign_ecdsa(
    secret_share: &str,
    key_id: &str,
    derivation_path: &[u32],
    hash: &Vec<u8>,
) -> Result<sodot_mpc::ecdsa::EcdsaSignature, Box<dyn std::error::Error>> {
    let ecdsa = Ecdsa::new(DEMO_HOST_URL.to_string());

    let signing_room_uuid = ecdsa
        .create_room(NonZeroU16::new(N).unwrap(), &get_api_key())
        .await?;

    let secret_share = SecretShare::<Ecdsa>::from(secret_share.to_string());

    let hash_hex = hex::encode(hash);

    let server_sign_handler = vertex::server_join_sign_message_room(
        "ecdsa",
        &signing_room_uuid.as_str(),
        key_id.to_string(),
        &derivation_path,
        &hash_hex,
    );

    let array: [u8; 32] = hash
        .as_slice()
        .try_into()
        .map_err(|_| "Hash must be exactly 32 bytes")?;

    let message_hash = MessageHash::from_hash(array);

    let signature_handle = ecdsa.sign(
        &signing_room_uuid,
        &secret_share,
        &message_hash,
        &derivation_path,
    );

    let (signature_result, _) = tokio::join!(signature_handle, server_sign_handler);

    let signature: sodot_mpc::ecdsa::EcdsaSignature = signature_result.unwrap();

    Ok(signature)
}

pub async fn xpub_ecdsa(
    serialized_secret_share: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let ecdsa = Ecdsa::new(DEMO_HOST_URL.to_string());

    // Restore the secret share from the serialized string
    let restored_share = SecretShare::<Ecdsa>::from(serialized_secret_share.to_string());

    let xpub: sodot_mpc::ExtendedPublicKey<Ecdsa> = ecdsa.get_xpub(&restored_share).unwrap();

    println!("Xpub: {}", xpub.clone().as_str());

    // let xpub_bytes = hex::decode(xpub.clone().as_str()).unwrap();
    let xpub_str = xpub.clone().as_str().to_string();
    Ok(xpub_str)
}

pub async fn derive_xpub_ecdsa(
    serialized_secret_share: &str,
    derivation_path: &[u32],
) -> Result<sodot_mpc::PublicKey<Ecdsa, 65>, Box<dyn std::error::Error>> {
    let ecdsa = Ecdsa::new(DEMO_HOST_URL.to_string());

    // Restore the secret share from the serialized string
    let restored_share = SecretShare::<Ecdsa>::from(serialized_secret_share.to_string());

    let xpub = ecdsa.get_xpub(&restored_share).unwrap();

    let public_key = ecdsa
        .derive_pubkey_from_xpub(&xpub, derivation_path)
        .unwrap();

    println!(
        "public_key compressed: {}",
        hex::encode(public_key.clone().compressed())
    );

    println!(
        "public_key uncompressed: {}",
        hex::encode(public_key.clone().uncompressed())
    );

    Ok(public_key)
}

#[cfg(test)]
mod test {
    use super::*;
    use kos::chains::Chain;
    use kos::chains::{icp::ICP, trx::TRX, xrp::XRP, ChainError};
    use kos_codec::{encode_for_broadcast, encode_for_signing, Transaction};

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
    async fn test_sodot_keygen_ecdsa() {
        let secret_share = keygen_ecdsa().await.unwrap();
        println!("Secret Share: {:?}", secret_share);
    }

    #[tokio::test]
    async fn test_sodot_derive_public_key_ecdsa() {
        // ICP

        let index = 1;

        let chain: TRX = TRX {};
        let path = chain.get_path(index, true);
        let mut derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ecdsa(&get_ecdsa_secret_share(), &derivation_path)
            .await
            .unwrap();

        println!(
            "TRX Pub Key: {:?}",
            hex::encode(pub_key.clone().uncompressed().to_vec())
        );
        let address = chain
            .get_address(pub_key.clone().uncompressed().to_vec())
            .unwrap();
        println!("TRX Address: {:?}", address);

        let address = chain.get_address(pub_key.compressed().to_vec()).unwrap();
        println!("TRX Address: {:?}", address);
    }

    #[tokio::test]
    async fn test_sodot_derive_address_ecdsa() {
        let pub_key = derive_public_key_ecdsa(&get_ecdsa_secret_share(), &[44, 690, 0, 0, 0])
            .await
            .unwrap();

        assert_eq!(
            hex::encode(pub_key.compressed().to_vec()),
            "f6e202fc4447c27aa125ad383386caf67902efd4bfdede5d7e7237c07ca7c0b6"
        );
    }

    #[tokio::test]
    async fn test_sodot_sign_ecdsa() {
        let hash = hex::decode("0a028f942208e9ee949f1f01ac4b40d0a5caaf9a335a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541e1534ab0f48ac52950d8971ad7471a42512c62a5121541c43903446f10397864b1bf92b3f7db1941586b1218c0843d70c1d9c6af9a33").unwrap();

        let index = 0;

        let chain: TRX = TRX {};
        let path = chain.get_path(index, true);
        println!("Derivation Path: {:?}", path);
        let derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        // let pub_key = derive_public_key_ecdsa(&get_ecdsa_secret_share(), &derivation_path)
        //     .await
        //     .unwrap();

        // println!("TRX Pub Key: {:?}", hex::encode(pub_key.clone()));
        // let address = chain.get_address(pub_key.clone()).unwrap();
        // println!("TRX Address: {:?}", address);

        let account = kos_codec::KosCodedAccount {
            chain_id: 1,
            address: "TWWcpS87vo9GFFvFBTCt1zznwDLpjMVPmL".to_string(),
            public_key: "0259292e7667ef0e358117d986592cc00b54f718fb53a67fd40d88fe37be05e788"
                .to_string(),
        };

        let transaction = Transaction {
            raw_data: hash,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        // let mut encode_for_sign = encode_for_signing(account.clone(), transaction).unwrap();
        // println!(
        //     "Transaction Raw for Sign: {:?}",
        //     hex::encode(encode_for_sign.clone().tx_hash)
        // );

        let hash = hex::decode("a6921f5bba75ad2fd699164c90c059ec760a336fa31929fc5b10fedee46c8a93")
            .unwrap();

        let signature = sign_ecdsa(
            &get_ecdsa_secret_share(),
            &get_ecdsa_key_id(),
            &derivation_path,
            &hash,
        )
        .await
        .unwrap();

        let mut signature_hash = signature.compact().to_vec();
        signature_hash.push(1); // append the recovery id
        println!("ECDSA Signature: {:?}", hex::encode(signature_hash.clone()));

        // let encode_for_broadcast = encode_for_broadcast(account, encode_for_sign).unwrap();
        // println!(
        //     "Transaction Raw for Broadcast: {:?}",
        //     hex::encode(encode_for_broadcast.raw_data)
        // );
        // println!(
        //     "Transaction Signature for Broadcast: {:?}",
        //     hex::encode(encode_for_broadcast.signature)
        // );

        // println!("ECDSA Signature: {:?}", signature);
    }

    #[tokio::test]
    async fn test_sodot_sign_XRP_ecdsa() {
        let hash = hex::decode("1200002405ea7dc16140000000000186a068400000000000000a81142d923804be41b8b5011991a1079890525a54fd4883144f7571cee107970f36b12285cc17e44c121ca0ae").unwrap();

        let index = 1;

        let chain: XRP = XRP {};
        let path = chain.get_path(index, true);
        println!("Derivation Path: {:?}", path);
        let derivation_path = parse_derivation_path(path).unwrap();
        println!("Derivation Path: {:?}", derivation_path);

        let pub_key = derive_public_key_ecdsa(&get_ecdsa_secret_share(), &derivation_path)
            .await
            .unwrap();

        println!(
            "XRP Pub Key: {:?}",
            hex::encode(pub_key.clone().compressed().to_vec())
        );
        let address = chain.get_address(pub_key.compressed().to_vec()).unwrap();
        println!("XRP Address: {:?}", address);

        let account = kos_codec::KosCodedAccount {
            chain_id: 4,
            address: "TWWcpS87vo9GFFvFBTCt1zznwDLpjMVPmL".to_string(),
            public_key: "0259292e7667ef0e358117d986592cc00b54f718fb53a67fd40d88fe37be05e788"
                .to_string(),
        };

        let transaction = Transaction {
            raw_data: hash,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let mut encode_for_sign = encode_for_signing(account.clone(), transaction).unwrap();
        println!(
            "Transaction Raw for Sign: {:?}",
            hex::encode(encode_for_sign.clone().tx_hash)
        );

        // let hash = hex::decode("a6921f5bba75ad2fd699164c90c059ec760a336fa31929fc5b10fedee46c8a93")
        //     .unwrap();

        let signature = sign_ecdsa(
            &get_ecdsa_secret_share(),
            &get_ecdsa_key_id(),
            &derivation_path,
            &encode_for_sign.tx_hash,
        )
        .await
        .unwrap();

        // println!(
        //     "ECDSA Signature: {:?}",
        //     hex::encode(signature.der().clone())
        // );

        let encode_for_broadcast = encode_for_broadcast(account, encode_for_sign).unwrap();
        println!(
            "Transaction Raw for Broadcast: {:?}",
            hex::encode(encode_for_broadcast.raw_data)
        );
        println!(
            "Transaction Signature for Broadcast: {:?}",
            hex::encode(encode_for_broadcast.signature)
        );

        // println!("ECDSA Signature: {:?}", signature);
    }
}
