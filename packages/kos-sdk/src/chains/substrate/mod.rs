#[cfg(test)]
mod tests {
    use sp_core::{crypto::Ss58Codec, sr25519};
    use subxt::config::substrate::SubstrateExtrinsicParamsBuilder as Params;
    use subxt::utils::AccountId32;
    use subxt::utils::MultiAddress;
    use subxt::{OnlineClient, SubstrateConfig};
    use subxt_signer::{bip39::Mnemonic, sr25519::Keypair};
    use sp_core::Pair;
    use subxt::config::substrate::SubstrateExtrinsicParamsBuilder;
    use sp_runtime::generic::Era;
    use base64::{Engine as _, alphabet, engine::{self, general_purpose}};


    // Generate an interface that we can use from the node's metadata.
    #[subxt::subxt(runtime_metadata_path = "artifacts/ksm-klever-node.scale")]
    pub mod substrate {}

    #[tokio::test]
    async fn test_subxt() {
        // Create a new API client, configured to talk to Polkadot nodes.
        let api = OnlineClient::<SubstrateConfig>::from_url("wss://kusama.node.klever.io")
            .await
            .unwrap();

        // Build a balance transfer extrinsic.
        let dest_publickey =
            sr25519::Public::from_ss58check("JH8gatLWwoDsMQQeXJuVaTsQVYJTEhywfTXuagucRCPYh8K")
                .unwrap();
        let dest = MultiAddress::Id(AccountId32::from(dest_publickey.0));
        let balance_transfer_tx = substrate::tx()
            .balances()
            .transfer_allow_death(dest, 100_000);

        let latest_block = api.blocks().at_latest().await.unwrap();

        let tx_params = Params::new()
            .tip(1_000)
            .mortal(latest_block.header(), 32)
            .build();

        // initialing account
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        let from = Keypair::from_phrase(&mnemonic, None).unwrap();

        let signed_tx = api
            .tx()
            .create_signed(&balance_transfer_tx, &from, tx_params)
            .await
            .unwrap();
        let result = signed_tx.validate().await;
        assert_eq!(result.is_ok(), true);
        let hex_ext = hex::encode(signed_tx.encoded());
        println!("hex_ext: {}", hex_ext);


        // Send the extrinsic to the node.
        let ext_result = signed_tx.submit().await;
        println!("ext_result: {:?}", ext_result);
        assert_eq!(ext_result.is_ok(), true);
        println!("tx_hash: {:?}", ext_result.unwrap().to_string());
    }

    // #[tokio::test]
    // async fn test_sign() {
    //     // Step 1: Generate a keypair from a mnemonic phrase
    //     let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    //     let mnemonic = Mnemonic::parse(phrase).unwrap();
    //     let from = Keypair::from_phrase(&mnemonic, None).unwrap();
    //
    //     // Step 2: Construct the transaction payload
    //     let dest_publickey = sr25519::Public::from_ss58check("JH8gatLWwoDsMQQeXJuVaTsQVYJTEhywfTXuagucRCPYh8K").unwrap();
    //     let dest = MultiAddress::Id(AccountId32::from(dest_publickey.0));
    //     let call =  substrate::tx()
    //         .balances()
    //         .transfer_allow_death(dest, 100_000);
    //
    //     // // Step 3: Create extrinsic parameters
    //     // let params = SubstrateExtrinsicParamsBuilder::new()
    //     //     .era(Era::Immortal, 0)
    //     //     .nonce(0)
    //     //     .tip(0);
    //     //
    //     // // Step 4: Sign the transaction using the keypair
    //     // let signature = from.sign(call.encode().as_slice());
    //     //
    //     // // Step 5: Construct the signed extrinsic
    //     // let extrinsic = sp_runtime::generic::UncheckedExtrinsic {
    //     //     signature: Some((from.public().into(), signature, params)),
    //     //     function: call,
    //     // };
    //     //
    //     // // Step 6: Encode the signed extrinsic to raw bytes
    //     // let raw_extrinsic = extrinsic.encode();
    //     //
    //     // println!("Signed transaction: {:?}", raw_extrinsic);
    //     //
    //     // Ok(())
    // }
    //
    // #[tokio::test]
    // async fn test_sign_2() {
    //     // Step 1: Generate a keypair from a mnemonic phrase
    //     let phrase = "permit best kiwi blast purchase cook grab present have hurdle quarter steak";
    //     let mnemonic = Mnemonic::parse(phrase).unwrap();
    //     let from = Keypair::from_phrase(&mnemonic, None).unwrap();
    //
    //     // Step 2: Decode the base64-encoded transaction
    //     let base64_tx = "BQMA/E3BuMkA3b4/J29/ZssDmcFEHlIf1YXQOhCb5SjoZzkoAKwAABdKDwAaAAAAkbFxuxWOLThI+iOp8cJRgvuOIDE7LB60khnaenDOkMORsXG7FY4tOEj6I6nxwlGC+44gMTssHrSSGdp6cM6QwwA=";
    //
    //     let raw_tx = general_purpose::STANDARD
    //         .decode(base64_tx).unwrap();
    //     println!("{:?}", raw_tx);
    //
    //     // Step 3: Deserialize the raw bytes into a transaction
    //     let mut raw_tx_cursor = std::io::Cursor::new(raw_tx);
    //     let call: substrate::runtime_types::pallet_balances::Call = Decode::decode(&mut raw_tx_cursor)?;
    //
    //     // Step 4: Create extrinsic parameters
    //     let params = SubstrateExtrinsicParamsBuilder::new()
    //         .era(Era::Immortal, 0)
    //         .nonce(0)
    //         .tip(0);
    //
    //     // Step 5: Sign the transaction using the keypair
    //     let signature = from.sign(call.encode().as_slice());
    //
    //     // Step 6: Construct the signed extrinsic
    //     let extrinsic = subxt::tx::UncheckedExtrinsic {
    //         signature: Some((from.public().into(), signature, params)),
    //         function: call,
    //     };
    //
    //     // Step 7: Encode the signed extrinsic to raw bytes
    //     let raw_signed_tx = extrinsic.encode();
    //
    //     println!("Signed transaction: {:?}", raw_signed_tx);
    //
    //     Ok(())
    //
    // }

}
