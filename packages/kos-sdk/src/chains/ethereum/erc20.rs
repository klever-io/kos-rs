use web3::ethabi::Contract;

// ERC20 contract ABI. This is a simplified ABI with only the `balanceOf` function.
const ERC20_CONTRACT_ABI: &str = r#"
[
  {
    "constant": true,
    "inputs": [
      {
        "name": "_owner",
        "type": "address"
      }
    ],
    "name": "balanceOf",
    "outputs": [
      {
        "name": "balance",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_to",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }

    ],
    "name": "transfer",
    "outputs": [
        {
            "name": "",
            "type": "bool"
        }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  }
]
"#;

pub fn get_contract_erc20() -> Contract {
    // Parse the ABI.
    Contract::load(ERC20_CONTRACT_ABI.as_bytes()).unwrap()
}
