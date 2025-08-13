use std::path::PathBuf;

fn main() {
    let mut config = prost_build::Config::new();
    config.btree_map(["."]);

    let protos = vec![
        "src/protos/tron/core/Discover.proto",
        "src/protos/tron/core/Tron.proto",
        "src/protos/tron/core/TronInventoryItems.proto",
        "src/protos/tron/core/contract/account_contract.proto",
        "src/protos/tron/core/contract/asset_issue_contract.proto",
        "src/protos/tron/core/contract/balance_contract.proto",
        "src/protos/tron/core/contract/common.proto",
        "src/protos/tron/core/contract/exchange_contract.proto",
        "src/protos/tron/core/contract/market_contract.proto",
        "src/protos/tron/core/contract/proposal_contract.proto",
        "src/protos/tron/core/contract/shield_contract.proto",
        "src/protos/tron/core/contract/smart_contract.proto",
        "src/protos/tron/core/contract/storage_contract.proto",
        "src/protos/tron/core/contract/vote_asset_contract.proto",
        "src/protos/tron/core/contract/witness_contract.proto",
    ];

    // Specify the output directory where the generated Rust code should be placed.
    config.out_dir("src/protos/generated/trx");

    // Add attribute to allow dead code for generated protobuf structs
    config.type_attribute(".", "#[allow(dead_code)]");

    config
        .compile_protos(&protos, &["src/protos/tron"])
        .unwrap();

    let out_dir = PathBuf::from("src/protos/generated/klv");

    config.extern_path(".google.protobuf", "crate::protos");
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.compile_well_known_types();

    let klv_protos = vec![
        "src/protos/klever/contracts.proto",
        "src/protos/klever/transaction.proto",
        "src/protos/klever/userAccountData.proto",
    ];

    config.out_dir(out_dir.clone());

    config
        .compile_protos(&klv_protos, &["src/protos/klever"])
        .unwrap();
}
