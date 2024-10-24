use crate::utils;
use kos_types::error::Error;
use serde_json::Value;

async fn create_call(url: String, method: &str, params: Value) -> Result<Value, Error> {
    let data = serde_json::json!({
        "method": method,
        "params": params,
        "id": 1,
        "jsonrpc": "2.0"
    })
    .to_string()
    .as_bytes()
    .to_vec();
    utils::http_post::<Value>(url, &data)
        .await
        .map_err(|e| e.into())
}

pub async fn get_metadata(url: &str) -> Result<String, Error> {
    let result = create_call(url.to_string(), "state_getMetadata", Value::Array(vec![])).await?;
    match result.get("result") {
        Some(metadata) => match metadata.as_str() {
            Some(metadata) => Ok(metadata.to_string()),
            None => Err(Error::InvalidTransaction("metadata not found".to_string())),
        },
        None => Err(Error::InvalidTransaction("metadata not found".to_string())),
    }
}
