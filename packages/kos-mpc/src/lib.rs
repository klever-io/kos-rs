mod providers;

use kos::chains::ChainError;

fn parse_derivation_path(path: String) -> Result<Vec<u32>, ChainError> {
    // Remove the 'm/' prefix if present
    let path = path.strip_prefix("m/").unwrap_or(&path);

    let mut components = Vec::new();

    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }

        // Remove the hardened indicator (') if present
        let cleaned_part = part.strip_suffix('\'').unwrap_or(part);

        // Parse the number
        match cleaned_part.parse::<u32>() {
            Ok(num) => components.push(num),
            Err(_) => return Err(ChainError::InvalidPublicKey),
        }
    }

    Ok(components)
}

pub async fn derive_public_key(
    share: &str,
    path: &str,
    algo: &str,
    compress: bool,
) -> Result<Vec<u8>, ChainError> {
    let path = parse_derivation_path(path.to_string())?;
    let mut public_key = vec![];

    match algo {
        "ed25519" => {
            public_key = providers::sodot::ed25519::derive_public_key_ed25519(share, &path)
                .await
                .map_err(|e| ChainError::ErrDerive)?
        }
        "ecdsa" => {
            let pbk = providers::sodot::ecdsa::derive_public_key_ecdsa(share, &path)
                .await
                .map_err(|e| ChainError::ErrDerive)?;

            if compress {
                public_key = pbk.compressed().to_vec();
            } else {
                public_key = pbk.uncompressed().to_vec();
            }
        }
        _ => return Err(ChainError::InvalidData("Unsupported algorithm".to_string())),
    };

    Ok(public_key)
}

pub async fn sign(
    share: &str,
    key_id: &str,
    path: &str,
    hash: &Vec<u8>,
    algo: &str,
) -> Result<Vec<u8>, ChainError> {
    let path = parse_derivation_path(path.to_string())?;

    let mut signature = Vec::new();

    match algo {
        "ed25519" => {
            signature = providers::sodot::ed25519::sign_ed25519(share, key_id, &path, hash)
                .await
                .map_err(|e| ChainError::ErrDerive)?
        }
        "ecdsa" => {
            let sodot_mpc_signature_ecdsa =
                providers::sodot::ecdsa::sign_ecdsa(share, key_id, &path, hash)
                    .await
                    .map_err(|e| ChainError::ErrDerive)?;

            signature = sodot_mpc_signature_ecdsa.compact().to_vec();
            // signature.push(sodot_mpc_signature_ecdsa.v());
            signature.push(1);
            // signature.push(value);
        }
        _ => return Err(ChainError::InvalidData("Unsupported algorithm".to_string())),
    };

    Ok(signature)
}

pub async fn sign_der(
    share: &str,
    key_id: &str,
    path: &str,
    hash: &Vec<u8>,
) -> Result<Vec<u8>, ChainError> {
    let path = parse_derivation_path(path.to_string())?;

    let sodot_mpc_signature_ecdsa = providers::sodot::ecdsa::sign_ecdsa(share, key_id, &path, hash)
        .await
        .map_err(|e| ChainError::ErrDerive)?;

    let signature = sodot_mpc_signature_ecdsa.der().to_vec();

    Ok(signature)
}

// ECDSA
pub async fn derive_public_key_xpub(
    share: &str,
    path: &str,
    compress: bool,
) -> Result<Vec<u8>, ChainError> {
    let path = parse_derivation_path(path.to_string())?;
    let mut public_key = vec![];

    let pbk = providers::sodot::ecdsa::derive_xpub_ecdsa(share, &path)
        .await
        .map_err(|e| ChainError::ErrDerive)?;

    if compress {
        public_key = pbk.compressed().to_vec();
    } else {
        public_key = pbk.uncompressed().to_vec();
    }

    Ok(public_key)
}

// ECDSA
pub async fn derive_xpub(share: &str) -> Result<String, ChainError> {
    let pbk = providers::sodot::ecdsa::xpub_ecdsa(share)
        .await
        .map_err(|e| ChainError::ErrDerive)?;

    Ok(pbk)
}
