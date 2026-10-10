//! Signed admission credential (grant).
//!
//! Contains the canonical fields + detached Ed25519 signature + issuer public key.
//! Private keys never appear here.
//!
//! Raw signing is crate-private. Public issuance must return only after a
//! concrete durable commit of the exact canonical signed bytes (see
//! `admission` / `store`).

use crate::canonical::{canonical_signing_bytes, CanonicalError, CanonicalFields};
use crate::keys::{IssuerSigningKey, IssuerVerifyingKey};
use crate::types::*;

/// A signed admission credential.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Canonical fields (the signed representation).
    pub fields: CanonicalFields,
    /// Detached Ed25519 signature over the canonical bytes.
    pub signature: [u8; 64],
    /// Issuer public key that produced this signature.
    pub issuer_public_key: [u8; 32],
}

/// Grant issuance/verification error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("canonical encoding error: {0}")]
    Canonical(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("issuer key mismatch")]
    IssuerKeyMismatch,
    #[error("issuer generation mismatch")]
    IssuerGenerationMismatch,
    #[error("deployment mismatch")]
    DeploymentMismatch,
    #[error("target identity mismatch")]
    TargetMismatch,
    #[error("credential expired")]
    Expired,
    #[error("credential not yet valid")]
    NotYetValid,
    #[error("schema mismatch")]
    SchemaMismatch,
    #[error("authority revision mismatch")]
    AuthorityRevisionMismatch,
    #[error("duration exceeds bound")]
    DurationExceedsBound,
    #[error("non-positive duration")]
    NonPositiveDuration,
    #[error("structural field rejection")]
    Structural,
}

impl From<CanonicalError> for GrantError {
    fn from(e: CanonicalError) -> Self {
        GrantError::Canonical(e.to_string())
    }
}

/// Authority binding the credential must match exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAuthority {
    pub issuer_public_key: [u8; 32],
    pub issuer_generation: u64,
    pub authority_revision: AuthorityRevision,
    pub deployment: DeploymentId,
    pub schema: String,
}

impl Grant {
    /// Raw sign of canonical bytes. **Crate-private**: public callers must
    /// use the commit seam so signed bytes are never returned unrecorded.
    pub(crate) fn sign_credential(
        fields: CanonicalFields,
        signing_key: &IssuerSigningKey,
    ) -> Result<Self, GrantError> {
        fields.validate_structure()?;
        let bytes = canonical_signing_bytes(&fields)?;
        let signature = signing_key.sign(&bytes);
        let public_key = signing_key.verifying_key();
        Ok(Self {
            fields,
            signature,
            issuer_public_key: *public_key.as_bytes(),
        })
    }

    /// SHA-256 over the exact canonical signed bytes.
    pub fn body_hash(&self) -> Result<[u8; 32], GrantError> {
        use sha2::{Digest, Sha256};
        let bytes = canonical_signing_bytes(&self.fields)?;
        Ok(Sha256::digest(&bytes).into())
    }

    /// Verify every signed field against independent expected authority and
    /// independent trusted receiver context. Never uses credential claims as
    /// their own expected values.
    pub fn verify_admission(
        &self,
        expected: &ExpectedAuthority,
        receiver: &ReceiverContext,
        now_ms: u64,
        max_lifetime_ms: u64,
    ) -> Result<(), GrantError> {
        // Structural + canonical
        self.fields.validate_structure()?;
        let bytes = canonical_signing_bytes(&self.fields)?;

        // Strict signature under the claimed issuer key
        let sig_key = IssuerVerifyingKey::from_bytes(&self.issuer_public_key)
            .map_err(|_| GrantError::SignatureInvalid)?;
        sig_key
            .verify_strict(&bytes, &self.signature)
            .map_err(|_| GrantError::SignatureInvalid)?;

        // Issuer binding: claimed key must be the pinned key
        if self.issuer_public_key != expected.issuer_public_key {
            return Err(GrantError::IssuerKeyMismatch);
        }
        if self.fields.schema != expected.schema {
            return Err(GrantError::SchemaMismatch);
        }
        if self.fields.deployment != expected.deployment {
            return Err(GrantError::DeploymentMismatch);
        }
        if self.fields.issuer_generation != expected.issuer_generation {
            return Err(GrantError::IssuerGenerationMismatch);
        }
        if self.fields.authority_revision != expected.authority_revision {
            return Err(GrantError::AuthorityRevisionMismatch);
        }

        // Independent receiver context — all signed identity fields
        if self.fields.computer != receiver.computer
            || self.fields.incarnation != receiver.incarnation
            || self.fields.account != receiver.account
            || self.fields.manager != receiver.manager
        {
            return Err(GrantError::TargetMismatch);
        }
        if self.fields.desktop_generation != receiver.desktop_generation {
            return Err(GrantError::TargetMismatch);
        }

        // Time: expired at now >= expires_at; not yet valid at now < issued_at
        if now_ms >= self.fields.expires_at.as_u64() {
            return Err(GrantError::Expired);
        }
        if now_ms < self.fields.issued_at.as_u64() {
            return Err(GrantError::NotYetValid);
        }

        let lifetime = checked_duration_ms(self.fields.issued_at, self.fields.expires_at)
            .map_err(|_| GrantError::NonPositiveDuration)?;
        if lifetime > max_lifetime_ms {
            return Err(GrantError::DurationExceedsBound);
        }

        Ok(())
    }

    /// Check if this grant's action scope permits the given operation.
    pub fn permits(&self, op: Operation) -> bool {
        self.fields.action_scope.permits(op)
    }
}

#[cfg(test)]
mod tests {
    // Verification is exercised through the public admit/issue boundary
    // in `admission` tests. These cover only crate-private signing hygiene.
    use super::*;
    use crate::canonical::SCHEMA_VERSION;

    fn sample() -> CanonicalFields {
        CanonicalFields {
            schema: SCHEMA_VERSION.to_string(),
            deployment: DeploymentId::new("deploy-1").unwrap(),
            issuer_generation: 1,
            authority_revision: AuthorityRevision::new("rev-1").unwrap(),
            computer: ComputerId::new("room7-a03").unwrap(),
            incarnation: IncarnationId::new("inc-abc").unwrap(),
            account: AccountId::new("acct-42").unwrap(),
            manager: ManagerId::new("mgr-7").unwrap(),
            action_scope: ActionScope::observe_only(),
            desktop_generation: DesktopGeneration::new(3).unwrap(),
            session_nonce: Nonce::new([1u8; 32]).unwrap(),
            issued_at: TimestampMs::new(1000).unwrap(),
            expires_at: TimestampMs::new(2000).unwrap(),
        }
    }

    #[test]
    fn sign_credential_binds_key() {
        let key = IssuerSigningKey::generate();
        let grant = Grant::sign_credential(sample(), &key).unwrap();
        assert_eq!(grant.issuer_public_key, *key.verifying_key().as_bytes());
        assert_eq!(grant.body_hash().unwrap().len(), 32);
    }

    #[test]
    fn observe_scope_permits_only_observe() {
        let key = IssuerSigningKey::generate();
        let grant = Grant::sign_credential(sample(), &key).unwrap();
        assert!(grant.permits(Operation::Observe));
        assert!(!grant.permits(Operation::Control));
    }
}
