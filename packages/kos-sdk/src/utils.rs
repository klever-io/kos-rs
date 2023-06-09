use kos_types::error::Error;

use reqwest;
use serde::de::DeserializeOwned;

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[allow(dead_code)]
#[cfg(not(target_arch = "wasm32"))]
pub fn http_get_block<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let body = reqwest::blocking::get(url).unwrap();
    body.json::<T>().map_err(|e| Error::from(e))
}

pub fn get_client() -> Result<reqwest::Client, Error> {
    let mut client = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    {
        client = client
            .user_agent(APP_USER_AGENT)
            .connect_timeout(std::time::Duration::from_secs(20))
            .timeout(std::time::Duration::from_secs(100));
    }

    client
        .build()
        .map_err(|e| Error::ReqwestError(e.to_string()))
}

pub async fn http_get<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let client = get_client()?;

    let body = client.get(url).send().await?;
    body.json::<T>().await.map_err(|e| Error::from(e))
}

pub async fn http_post<T: DeserializeOwned>(url: String, data: &Vec<u8>) -> Result<T, Error> {
    let client = get_client()?;

    client
        .post(url)
        .header("Content-Type", "application/json")
        .body(data.to_vec())
        .send()
        .await
        .map_err(|e| Error::from(e))?
        .json::<T>()
        .await
        .map_err(|e| Error::from(e))
}

pub fn get_node_url(name: &str) -> String {
    std::env::var(format!("NODE.{}", name)).unwrap_or("".to_string())
}