use reqwest::{self, Error};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

#[derive(Deserialize, Debug)]
pub struct CreateResponseBody {
    pub key_id: String,
    pub keygen_id: String,
}

#[derive(Serialize, Debug)]
pub struct ServerJoinRoomRequestBody {
    pub num_parties: NonZeroU16,
    pub others_keygen_ids: Vec<String>,
    pub relay_address: String,
    pub room_uuid: String,
    pub threshold: NonZeroU16,
    pub key_id: String,
}

#[derive(Serialize, Debug)]
pub struct ServerJoinSignRoomRequestBody {
    pub msg: String,
    pub derivation_path: Vec<u32>,
    pub extra_data: String,
    pub hash_algo: String,
    pub room_uuid: String,
    pub key_id: String,
}

const N: u16 = 2;
const T: u16 = 2;
const VERTEX_URL: &str = "https://vertex-klv.sodot.dev";
const DEMO_HOST_URL: &str = "demo.sodot.dev";

fn get_api_key() -> String {
    std::env::var("VERTEX_API_KEY").unwrap()
}

pub async fn generate_key(algo: &str) -> Result<CreateResponseBody, Error> {
    let client = reqwest::Client::new();
    let url = format!("{}/{}/create", VERTEX_URL, algo); // Replace with your actual URL

    let response = client
        .get(url)
        .header("AUTHORIZATION", format!("{}", &get_api_key()))
        .send()
        .await?;

    let response_body: CreateResponseBody = response.json().await?;
    println!("Success! Response: {:?}", response_body);
    Ok(response_body)
}

// Keygen room
pub async fn server_join_room(
    algo: &str,
    roomId: &str,
    keyId: String,
    keygenIds: Vec<String>,
) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!("{}/{}/keygen", VERTEX_URL, algo); // Replace with your actual URL

    let request = client
        .post(url)
        .header("AUTHORIZATION", format!("{}", &get_api_key()))
        .json(&ServerJoinRoomRequestBody {
            num_parties: NonZeroU16::new(N).unwrap(),
            others_keygen_ids: keygenIds,
            relay_address: DEMO_HOST_URL.to_string(),
            room_uuid: roomId.to_string(),
            threshold: NonZeroU16::new(T).unwrap(),
            key_id: keyId,
        });

    let response = request.send().await?;
    let body = response.text().await?;
    println!("{}", body);

    Ok(())
}

// Sign message room
pub async fn server_join_sign_message_room(
    algo: &str,
    room_id: &str,
    key_id: String,
    derivation_path: &[u32],
    hash_to_sign: &str,
) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!("{}/{}/sign", VERTEX_URL, algo); // Replace with your actual URL

    let request = client
        .post(url)
        .header("AUTHORIZATION", format!("{}", &get_api_key()))
        .json(&ServerJoinSignRoomRequestBody {
            msg: hash_to_sign.to_string(),
            derivation_path: derivation_path.to_vec(),
            extra_data: "".to_string(),
            hash_algo: "none".to_string(),
            room_uuid: room_id.to_string(),
            key_id: key_id,
        });

    let response = request.send().await?;
    let body = response.text().await?;
    println!("{}", body);

    Ok(())
}
