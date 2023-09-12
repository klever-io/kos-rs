#[cfg(test)]
mod tests {
    use std::assert_eq;
    use std::str;

    use crate::chains::klever::*;
    use crate::models::SendOptions;
    use hex::FromHex;
    use kos_types::Bytes32;

    const DEFAULT_PRIVATE_KEY: &str =
        "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d";
    const DEFAULT_ADDRESS: &str = "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Ed25519KeyPair::new(b.into());
        KeyPair::from(kp)
    }

    #[test]
    fn test_get_balance() {
        let balance = tokio_test::block_on(KLV::get_balance(
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            Some("KLV".to_string()),
            None,
        ))
        .unwrap();
        println!("balance: {}", balance.to_string());
        println!("balance: {}", balance.with_precision(6));

        assert_eq!("0", balance.to_string());
    }

    #[test]
    fn test_broadcast() {
        let klv_tx: kos_proto::klever::Transaction = serde_json::from_str(
            "{\"RawData\":{\"Nonce\":13,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBIDS0xWGAo=\"}}],\"KAppFee\":500000,\"BandwidthFee\":1000000,\"Version\":1,\"ChainID\":\"MTAwNDIw\"},\"Signature\":[\"O7C2MjTUMauWl8kfeJjgwDnFLkiDqY2U23s6AWzTstut63FnZeKC3EcxY0DiAgzf5PQ1+jeC2dIx3+pP7BHlBQ==\"]}",
        ).unwrap();

        let to_broadcast = crate::models::Transaction {
            chain: crate::chain::Chain::KLV,
            sender: "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
            hash: Hash::new("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            data: Some(TransactionRaw::Klever(klv_tx)),
        };

        let result = tokio_test::block_on(KLV::broadcast(
            to_broadcast,
            Some("https://node.testnet.klever.finance".to_string()),
        ));

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("lowerNonceInTx: true"))
    }

    #[test]
    fn test_send() {
        let result = tokio_test::block_on(KLV::send(
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
            "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm".to_string(),
            BigNumber::from(10),
            None,
            Some("https://node.testnet.klever.finance".to_string()),
        ));

        assert!(result.is_ok());
        match result.unwrap().data {
            Some(TransactionRaw::Klever(tx)) => {
                let raw = &tx.raw_data.unwrap();
                assert!(raw.nonce > 0);
                assert_eq!(raw.k_app_fee, 500000);
                assert_eq!(raw.bandwidth_fee, 1000000);
                assert!(raw.kda_fee.is_none());

                assert_eq!(raw.contract.len(), 1);
                let c: kos_proto::klever::TransferContract =
                    kos_proto::unpack_from_option_any(&raw.contract.get(0).unwrap().parameter)
                        .unwrap();

                assert_eq!(c.amount, 10);
                assert_eq!(c.asset_id.len(), 0);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_send_kda() {
        let kda = "KFI".to_string();
        // create KLV send options
        let klv_options = kos_proto::options::KLVOptions {
            kda: Some(kda.clone()),
            ..Default::default()
        };

        let options = SendOptions::new_klever_send_options(klv_options);

        let result = tokio_test::block_on(KLV::send(
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
            "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm".to_string(),
            BigNumber::from(10),
            Some(options),
            Some("https://node.testnet.klever.finance".to_string()),
        ));

        assert!(result.is_ok());
        match result.unwrap().data {
            Some(TransactionRaw::Klever(tx)) => {
                let raw = &tx.raw_data.unwrap();
                assert!(raw.nonce > 0);
                assert_eq!(raw.k_app_fee, 500000);
                assert_eq!(raw.bandwidth_fee, 1000000);
                assert!(raw.kda_fee.is_none());

                assert_eq!(raw.contract.len(), 1);
                let c: kos_proto::klever::TransferContract =
                    kos_proto::unpack_from_option_any(&raw.contract.get(0).unwrap().parameter)
                        .unwrap();

                assert_eq!(c.amount, 10);
                assert_eq!(str::from_utf8(&c.asset_id).unwrap(), kda);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_address_from_mnemonic() {
        let path = KLV::get_path(0).unwrap();
        let kp = KLV::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", &path, None).unwrap();
        let address = KLV::get_address_from_keypair(&kp).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_address_from_private_key() {
        let address = KLV::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address.to_string());
    }

    #[test]
    fn test_sign_message() {
        let message = "Hello World";
        let kp = get_default_secret();
        let signature = KLV::sign_message(message.as_bytes(), &kp).unwrap();
        assert_eq!(
            "38b3fd1e4d5a34291dddb2c6ca66e857c1696f3160981ca6abb8a78087f86b6163314cadd16179239d38201ba91c97aa201b7f38ecfff50c7f0448da67bf5a05",
            hex::encode(signature)
        );
    }

    #[test]
    fn test_verify_message() {
        let message = "Hello World";
        let kp = get_default_secret();
        let signature = hex::decode("38b3fd1e4d5a34291dddb2c6ca66e857c1696f3160981ca6abb8a78087f86b6163314cadd16179239d38201ba91c97aa201b7f38ecfff50c7f0448da67bf5a05").unwrap() ;
        let address = KLV::get_address_from_keypair(&kp).unwrap();
        let result = KLV::verify_message_signature(message.as_bytes(), &signature, &address);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_tx_from_raw() {
        let raw = "{\"RawData\":{\"BandwidthFee\":1000000,\"ChainID\":\"MTAwNDIw\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK\"}}],\"KAppFee\":500000,\"Nonce\":39,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Version\":1}}";

        let tx = KLV::tx_from_raw(raw);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(tx.chain, crate::chain::Chain::KLV);
        assert_eq!(
            tx.sender,
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        );
        assert_eq!(
            tx.hash.to_string(),
            "1e61c51f0d230f4855dc9b8935b47b9019887baf02be75d364a4068083833c15"
        );
        match tx.data.unwrap() {
            TransactionRaw::Klever(klv_tx) => {
                let raw = &klv_tx.raw_data.unwrap();
                assert_eq!(raw.nonce, 39);
                assert_eq!(raw.contract.len(), 1);
                assert_eq!(raw.bandwidth_fee, 1000000);
                assert_eq!(raw.k_app_fee, 500000);

                let c: kos_proto::klever::TransferContract =
                    kos_proto::unpack_from_option_any(&raw.contract.get(0).unwrap().parameter)
                        .unwrap();

                assert_eq!(c.amount, 10);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_validate_address_ok() {
        let list = [
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm",
        ];

        for addr in list.iter() {
            let result = KLV::validate_address(addr, None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true, "address: {}", addr);
        }
    }

    #[test]
    fn test_validate_address_fail() {
        let list = [
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlaz",
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy1",
            "klv2usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "klvusdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "bnb1ztx5rf7jx28k3xnemftcq3kfgm3yhfvfmhm456",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        ];

        for addr in list.iter() {
            let result = KLV::validate_address(addr, None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false, "address: {}", addr);
        }
    }
}
