use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=../../env");
    println!("cargo:rerun-if-env-changed=KOS_MNEMONIC_FOR_TEST");

    if let Ok(env_content) = fs::read_to_string("../../.env") {
        let mut mnemonic: Option<String> = None;
        for line in env_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                if key == "KOS_MNEMONIC_FOR_TEST" {
                    let value = value.trim().trim_matches('"').trim_matches('\'').to_owned();
                    mnemonic = Some(value);
                }
            }
        }
        match mnemonic {
            Some(v) => println!("cargo:rustc-env=KOS_MNEMONIC_FOR_TEST={}", v),
            None    => println!("cargo:rustc-env=KOS_MNEMONIC_FOR_TEST=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        }
    } else {
        println!("cargo:rustc-env=KOS_MNEMONIC_FOR_TEST=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }
}
