/// Key schemes supported/recognized in NEAR Protocol.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NearKeySchema {
    Ed25519,
    Secp256k1,
    MlDsa65,
}

impl NearKeySchema {
    /// Extracts the schema prefix (if present) from a string key or path.
    /// Returns `Some((schema, rest_of_string))` if a known prefix is found.
    pub fn parse_prefix(input: &str) -> Option<(Self, &str)> {
        let trimmed = input.trim();
        if let Some((prefix, rest)) = trimmed.split_once(':') {
            if prefix.eq_ignore_ascii_case("ed25519") {
                Some((NearKeySchema::Ed25519, rest))
            } else if prefix.eq_ignore_ascii_case("secp256k1") {
                Some((NearKeySchema::Secp256k1, rest))
            } else if prefix.eq_ignore_ascii_case("ml-dsa-65")
                || prefix.eq_ignore_ascii_case("mldsa65")
            {
                Some((NearKeySchema::MlDsa65, rest))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the string representation of the schema prefix.
    pub fn as_str(&self) -> &'static str {
        match self {
            NearKeySchema::Ed25519 => "ed25519",
            NearKeySchema::Secp256k1 => "secp256k1",
            NearKeySchema::MlDsa65 => "ml-dsa-65",
        }
    }
}

impl core::fmt::Display for NearKeySchema {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_parse_prefix_valid() {
        assert_eq!(
            NearKeySchema::parse_prefix("ed25519:samplekey"),
            Some((NearKeySchema::Ed25519, "samplekey"))
        );
        assert_eq!(
            NearKeySchema::parse_prefix("ED25519:samplekey"),
            Some((NearKeySchema::Ed25519, "samplekey"))
        );
        assert_eq!(
            NearKeySchema::parse_prefix("secp256k1:samplekey"),
            Some((NearKeySchema::Secp256k1, "samplekey"))
        );
        assert_eq!(
            NearKeySchema::parse_prefix("SECP256K1:samplekey"),
            Some((NearKeySchema::Secp256k1, "samplekey"))
        );
        assert_eq!(
            NearKeySchema::parse_prefix("ml-dsa-65:samplekey"),
            Some((NearKeySchema::MlDsa65, "samplekey"))
        );
        assert_eq!(
            NearKeySchema::parse_prefix("mldsa65:samplekey"),
            Some((NearKeySchema::MlDsa65, "samplekey"))
        );
    }

    #[test]
    fn test_parse_prefix_invalid() {
        assert_eq!(NearKeySchema::parse_prefix("samplekey_noprefix"), None);
        assert_eq!(NearKeySchema::parse_prefix("unknown:samplekey"), None);
        assert_eq!(NearKeySchema::parse_prefix(""), None);
    }

    #[test]
    fn test_as_str_and_display() {
        assert_eq!(NearKeySchema::Ed25519.as_str(), "ed25519");
        assert_eq!(NearKeySchema::Secp256k1.as_str(), "secp256k1");
        assert_eq!(NearKeySchema::MlDsa65.as_str(), "ml-dsa-65");

        assert_eq!(format!("{}", NearKeySchema::Ed25519), "ed25519");
        assert_eq!(format!("{}", NearKeySchema::Secp256k1), "secp256k1");
        assert_eq!(format!("{}", NearKeySchema::MlDsa65), "ml-dsa-65");
    }
}
