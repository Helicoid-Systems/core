//! Ed25519 key management. Signing private keys never implement Debug or serde.
//!
//! The raw signer is crate-private: public issuance must go through the
//! durable commit seam so signed bytes never leave before a committed record.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

/// Error type for key operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    VerifyFailed,
}

/// Issuer signing key. Private key material never exposed via Debug or serde.
///
/// Kept public only so development fixtures can mint keys; the signing path
/// used by credentials is crate-private (`sign` is `pub(crate)`).
pub struct IssuerSigningKey {
    signing: SigningKey,
}

// Explicitly no Debug impl for IssuerSigningKey — private key must not leak.

impl IssuerSigningKey {
    /// Generate a new key from OS RNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self {
            signing: SigningKey::from_bytes(&secret),
        }
    }

    /// Load from raw 32 bytes (test/fixtures only).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> IssuerVerifyingKey {
        IssuerVerifyingKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Sign a message. Crate-private: raw signatures are not a public API.
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.signing.sign(message);
        sig.to_bytes()
    }
}

/// Issuer verifying key. Safe to Debug and serialize.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuerVerifyingKey {
    verifying: VerifyingKey,
}

impl std::fmt::Debug for IssuerVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerVerifyingKey")
            .field("bytes", &hex::encode(self.verifying.as_bytes()))
            .finish()
    }
}

impl IssuerVerifyingKey {
    /// From raw 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        let verifying = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Self { verifying })
    }

    /// Raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying.as_bytes()
    }

    /// Strict detached-signature verification (rejects weak/ non-canonical forms).
    pub fn verify_strict(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), KeyError> {
        use ed25519_dalek::Signature;
        let sig = Signature::from_bytes(signature);
        self.verifying
            .verify_strict(message, &sig)
            .map_err(|_| KeyError::VerifyFailed)
    }
}

/// Generate random 32 bytes from OS RNG (for nonces, fixtures).
pub fn random_32() -> [u8; 32] {
    let mut rng = OsRng;
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_strict_roundtrip() {
        let key = IssuerSigningKey::generate();
        let pub_key = key.verifying_key();
        let msg = b"test message";
        let sig = key.sign(msg);
        assert!(pub_key.verify_strict(msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let key = IssuerSigningKey::generate();
        let pub_key = key.verifying_key();
        let sig = key.sign(b"original");
        assert!(pub_key.verify_strict(b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key1 = IssuerSigningKey::generate();
        let key2 = IssuerSigningKey::generate();
        let sig = key1.sign(b"msg");
        assert!(key2.verifying_key().verify_strict(b"msg", &sig).is_err());
    }

    #[test]
    fn nonces_are_random() {
        let a = random_32();
        let b = random_32();
        assert_ne!(a, b);
    }

    #[test]
    fn private_key_debug_not_implemented() {
        // Compile-time guard: if Debug were derived this would still compile,
        // so we only assert the public verifying key formats safely.
        let key = IssuerSigningKey::generate();
        let _ = format!("{:?}", key.verifying_key());
    }
}
