use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=.env");

    if let Ok(env_content) = fs::read_to_string("../../.env") {
        for line in env_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"').trim_matches('\'');
                println!("cargo:rustc-env={}={}", key, value);
            }
        }
    } else {
        println!("cargo:rustc-env=KOS_MNEMONIC_FOR_TEST=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }
}
