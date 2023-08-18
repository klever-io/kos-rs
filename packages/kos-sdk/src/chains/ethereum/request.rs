use super::address::Address;

use kos_types::{error::Error, number::BigNumber};

use web3::{transports::Http, types::U256, Web3};

pub fn new_transport(url: &str) -> Result<Http, Error> {
    let transport =
        web3::transports::Http::new(url).map_err(|e| Error::TransportError(e.to_string()))?;
    Ok(transport)
}

pub fn get_web3(url: &str) -> Result<Web3<Http>, Error> {
    let transport = new_transport(url)?;
    let web3 = Web3::new(transport);
    Ok(web3)
}

pub async fn call(url: &str, from: Address, to: Address, data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let call = web3::types::CallRequest {
        from: Some(from.into()),
        to: Some(to.into()),
        gas: None,
        gas_price: None,
        value: None,
        data: Some(data.into()),
        ..Default::default()
    };

    let web3 = get_web3(url)?;
    let result = web3
        .eth()
        .call(call, None)
        .await
        .map_err(|e| Error::TransportError(e.to_string()))?;

    Ok(result.0)
}

pub async fn get_balance(url: &str, address: Address) -> Result<BigNumber, Error> {
    let web3 = get_web3(url)?;
    let balance = web3
        .eth()
        .balance(address.into(), None)
        .await
        .map_err(|e| Error::TransportError(e.to_string()))?;
    balance.to_string().try_into()
}

pub async fn get_nonce(url: &str, address: Address) -> Result<u64, Error> {
    let web3 = get_web3(url)?;
    let nonce = web3
        .eth()
        .transaction_count(address.into(), None)
        .await
        .map_err(|e| Error::TransportError(e.to_string()))?;
    Ok(nonce.as_u64())
}

/// Call a contract without changing the state of the blockchain to estimate gas usage.
pub async fn estimate_gas(
    url: &str,
    from: Address,
    to: Address,
    gas_price: Option<U256>,
    value: Option<U256>,
    data: Option<Vec<u8>>,
) -> Result<U256, Error> {
    let req = web3::types::CallRequest {
        from: Some(from.into()),
        to: Some(to.into()),
        gas: None,
        gas_price,
        value,
        data: data.map(|data| data.into()),
        ..Default::default()
    };

    let web3 = get_web3(url)?;
    web3.eth()
        .estimate_gas(req, None)
        .await
        .map_err(|e| Error::TransportError(e.to_string()))
}

/// Get current recommended gas price
pub async fn gas_price(url: &str) -> Result<U256, Error> {
    let web3 = get_web3(url)?;
    web3.eth()
        .gas_price()
        .await
        .map_err(|e| Error::TransportError(e.to_string()))
}

pub async fn base_fee(url: &str) -> Result<U256, Error> {
    let web3 = get_web3(url)?;
    let block = web3
        .eth()
        .block(web3::types::BlockId::Number(
            web3::types::BlockNumber::Pending,
        ))
        .await
        .map_err(|e| Error::TransportError(e.to_string()))?
        .unwrap();

    // get block base fee
    let base_fee = block.base_fee_per_gas.unwrap_or(U256::zero());

    Ok(base_fee)
}

/// Broadcast ETH transaction
pub async fn broadcast(url: &str, tx_raw: Vec<u8>) -> Result<String, Error> {
    let web3 = get_web3(url)?;
    Ok(web3
        .eth()
        .send_raw_transaction(tx_raw.into())
        .await
        .map_err(|e| Error::TransportError(e.to_string()))?
        .to_string())
}
