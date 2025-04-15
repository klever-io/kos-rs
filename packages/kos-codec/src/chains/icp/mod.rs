use kos::chains::util::{byte_vectors_to_bytes, bytes_to_byte_vectors};
use kos::chains::{ChainError, Transaction};
use tiny_json_rs::serializer;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let hex = hex::decode(transaction.raw_data.clone()).map_err(|_| ChainError::DecodeRawTx)?;
    let raw_data_str = String::from_utf8(hex).map_err(|_| ChainError::DecodeRawTx)?;

    let wrapped_data = format!("{{\"hashes\":{}}}", raw_data_str);

    #[derive(tiny_json_rs::Deserialize)]
    struct HashContainer {
        hashes: Vec<String>,
    }

    let container: HashContainer =
        tiny_json_rs::decode(wrapped_data).map_err(|_| ChainError::DecodeHash)?;

    let icp_hashes = container.hashes;

    let mut hashes = Vec::new();

    for hash_hex in icp_hashes {
        hashes.push(hex::decode(hash_hex).unwrap());
    }

    transaction.tx_hash = byte_vectors_to_bytes(&hashes);
    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let signatures = bytes_to_byte_vectors(transaction.signature)?;

    let mut signatures_vec = Vec::new();
    for signature in signatures {
        signatures_vec.push(hex::encode(signature));
    }

    let signatures_json = tiny_json_rs::encode(signatures_vec);
    transaction.signature = signatures_json.into_bytes();
    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tx() {
        let raw_tx = hex::decode("35623232333036313336333933363333333236343337333233363335333733313337333533363335333733333337333433353332333133373635333533363336333433393636363633323331333233383333333636363330363133323332333633323336333736363333333036333631333033303635333836353334363633323635333833333334363236313336363333303634333236343338333233343332333733323336333933303337333033303232326332323330363133363339333633333332363433373332333633353337333133373335333633353337333333373334333136323331333433303632363236343337333633353337333136333330363133333334333333333331333333313338333533343333333736323635333836323338363236333334363433353635333233383339333833303331363136353631333133373635363133303336363136363332333036343331363533393337333532323564").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let mut result = encode_for_sign(tx.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash.clone()),
            "020000002b0000000a69632d726571756573745217e56649ff212836f0a226267f30ca00e8e4f2e834ba6c0d2d8242726907002b0000000a69632d726571756573741b140bbd76571c0a343313185437be8b8bc4d5e289801aea17ea06af20d1e975"
        );

        result.signature = hex::decode("0200000040000000cfb3e72d741521a803a6a3769864413eef9500dfb5fb488d68b84066f8643785a69da83e2ec4c936e8408272ad96d1d461d4f91a26dd9fb43d21f9130a75b9064000000097ca0c2eef5673ee0528b3afa468cfd2bd3384b1dd98d3e4c9171855bed8b915c8b971ab8a842b5fb8fc78fdb7ca819753f355229d1fc0d57c3709e0615c0504").unwrap();

        let result = encode_for_broadcast(result.clone()).unwrap();

        assert_eq!(
            hex::encode(result.signature),
            "5b226366623365373264373431353231613830336136613337363938363434313365656639353030646662356662343838643638623834303636663836343337383561363964613833653265633463393336653834303832373261643936643164343631643466393161323664643966623433643231663931333061373562393036222c223937636130633265656635363733656530353238623361666134363863666432626433333834623164643938643365346339313731383535626564386239313563386239373161623861383432623566623866633738666462376361383139373533663335353232396431666330643537633337303965303631356330353034225d"
        );
    }
}
