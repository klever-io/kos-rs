use kos_types::error::Error;

use serde::de::DeserializeOwned;

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[allow(dead_code)]
#[cfg(not(target_arch = "wasm32"))]
pub fn http_get_block<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let body = reqwest::blocking::get(url).unwrap();
    body.json::<T>().map_err(Error::from)
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

/// HTTP GET request
pub async fn http_get<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let client = get_client()?;

    let body = client.get(url).send().await?;
    body.json::<T>().await.map_err(Error::from)
}

/// HTTP GET request with basic auth
pub async fn http_get_auth<T: DeserializeOwned>(url: String) -> Result<T, Error> {
    let client = get_client()?;

    let body = basic_auth(client.get(url)).send().await?;
    body.json::<T>().await.map_err(Error::from)
}

/// HTTP POST request
pub async fn http_post<T: DeserializeOwned>(url: String, data: &[u8]) -> Result<T, Error> {
    let client = get_client()?;

    client
        .post(url)
        .header("Content-Type", "application/json")
        .body(data.to_vec())
        .send()
        .await
        .map_err(Error::from)?
        .json::<T>()
        .await
        .map_err(Error::from)
}

/// HTTP POST request with basic auth
pub async fn http_post_auth<T: DeserializeOwned>(url: String, data: &[u8]) -> Result<T, Error> {
    let client = get_client()?;

    basic_auth(client.post(url))
        .header("Content-Type", "application/json")
        .body(data.to_vec())
        .send()
        .await
        .map_err(Error::from)?
        .json::<T>()
        .await
        .map_err(Error::from)
}

pub fn get_node_url(name: &str) -> String {
    std::env::var(format!("NODE_{}", name)).unwrap_or("".to_string())
}

pub fn basic_auth(client: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(user) = std::env::var("KOS_API_USER") {
        let pass: Option<String> = std::env::var("KOS_API_PASS").ok();
        return client.basic_auth(user, pass);
    }

    return client;
}