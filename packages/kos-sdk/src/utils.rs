use kos_types::error::Error;

use reqwest;
use serde::de::DeserializeOwned;

#[allow(dead_code)]
#[cfg(not(target_arch = "wasm32"))]
pub fn http_get_block<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let body = reqwest::blocking::get(url).unwrap();
    body.json::<T>().map_err(|e| Error::from(e))
}

pub async fn http_get<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let body = reqwest::get(url).await.unwrap();
    body.json::<T>().await.map_err(|e| Error::from(e))
}
