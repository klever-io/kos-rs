use web3::ethabi::Contract;

// TRC20 contract ABI. This is a simplified ABI with only the `transfer` function.
const TRC20_CONTRACT_ABI: &str = r#"
[
   {
      "constant":false,
      "inputs":[
         {
            "name":"_from",
            "type":"address"
         },
         {
            "name":"_to",
            "type":"address"
         },
         {
            "name":"_value",
            "type":"uint256"
         }
      ],
      "name":"transferFrom",
      "outputs":[
         {
            "name":"",
            "type":"bool"
         }
      ],
      "payable":false,
      "stateMutability":"nonpayable",
      "type":"function"
   },
   {
      "constant":false,
      "inputs":[
         {
            "name":"_to",
            "type":"address"
         },
         {
            "name":"_value",
            "type":"uint256"
         }
      ],
      "name":"transfer",
      "outputs":[
         {
            "name":"",
            "type":"bool"
         }
      ],
      "payable":false,
      "stateMutability":"nonpayable",
      "type":"function"
   }
]
"#;

pub fn get_contract_trc20() -> Contract {
    // Parse the ABI.
    Contract::load(TRC20_CONTRACT_ABI.as_bytes()).unwrap()
}
