//! Canonical signing representation with domain separation.
//!
//! Deterministic byte layout for Ed25519 signatures. No JSON ambiguity.
//! All fields are length-prefixed or fixed-width. Domain tag + version
//! prefix every signed message.
//!
//! Decoding is total: every truncation is a clean error, never a panic.
//! The entire body is length-bounded before parsing.

use crate::types::*;

/// Domain separation tag for admission credentials.
pub const DOMAIN_TAG: &[u8] = b"HAL-AUTH-ADMISSION";

/// Canonical schema version (candidate, not a production freeze).
pub const SCHEMA_VERSION: &str = "v1";

/// Hard bound on the entire canonical body. Larger inputs are rejected
/// before any field is parsed.
pub const MAX_CANONICAL_BODY: usize = 4096;

/// Maximum operations in one action scope.
pub const MAX_SCOPE_OPS: usize = 3;

/// Canonical signing error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("field too long for canonical encoding: {0}")]
    FieldTooLong(&'static str),
    #[error("empty field in canonical encoding: {0}")]
    EmptyField(&'static str),
    #[error("body exceeds bound: {0} > {MAX_CANONICAL_BODY}")]
    BodyTooLarge(usize),
    #[error("truncated canonical body at {0}")]
    Truncated(&'static str),
    #[error("trailing bytes after canonical body")]
    TrailingBytes,
    #[error("unknown operation opcode {0}")]
    UnknownOp(u8),
    #[error("duplicate operation in scope")]
    DuplicateOp,
    #[error("zero value for {0}")]
    ZeroValue(&'static str),
    #[error("invalid time bounds")]
    InvalidTimeBounds,
    #[error("identifier rejected in canonical decode")]
    InvalidId,
}

/// Encode a length-prefixed byte string (u32 BE length + bytes).
fn encode_lp(out: &mut Vec<u8>, data: &[u8], field: &'static str) -> Result<(), CanonicalError> {
    if data.is_empty() {
        return Err(CanonicalError::EmptyField(field));
    }
    if data.len() > u32::MAX as usize {
        return Err(CanonicalError::FieldTooLong(field));
    }
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// Encode a fixed 8-byte integer (big-endian).
fn encode_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Encode a fixed 32-byte value.
fn encode_32(out: &mut Vec<u8>, v: &[u8; 32]) {
    out.extend_from_slice(v);
}

/// Full credential fields used in the canonical signing representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalFields {
    pub schema: String,
    pub deployment: DeploymentId,
    pub issuer_generation: u64,
    pub authority_revision: AuthorityRevision,
    pub computer: ComputerId,
    pub incarnation: IncarnationId,
    pub account: AccountId,
    pub manager: ManagerId,
    pub action_scope: ActionScope,
    pub desktop_generation: DesktopGeneration,
    pub session_nonce: Nonce,
    pub issued_at: TimestampMs,
    pub expires_at: TimestampMs,
}

impl CanonicalFields {
    /// Structural checks applied on every public issuance/admission path:
    /// non-zero generation/nonce/desktop, positive duration, timestamps fit.
    pub fn validate_structure(&self) -> Result<(), CanonicalError> {
        if self.issuer_generation == 0 {
            return Err(CanonicalError::ZeroValue("issuer_generation"));
        }
        if self.desktop_generation.as_u64() == 0 {
            return Err(CanonicalError::ZeroValue("desktop_generation"));
        }
        if self.session_nonce.as_bytes() == &[0u8; 32] {
            return Err(CanonicalError::ZeroValue("nonce"));
        }
        if self.issued_at.to_i64().is_err() || self.expires_at.to_i64().is_err() {
            return Err(CanonicalError::InvalidTimeBounds);
        }
        if self.expires_at.as_u64() <= self.issued_at.as_u64() {
            return Err(CanonicalError::InvalidTimeBounds);
        }
        if self.action_scope.operations().len() > MAX_SCOPE_OPS {
            return Err(CanonicalError::FieldTooLong("scope_ops"));
        }
        Ok(())
    }
}

/// Build the canonical signing bytes. Deterministic; same fields → same bytes.
///
/// Layout:
///   DOMAIN_TAG (fixed) || 0x00 || schema (LP) || deployment (LP) ||
///   issuer_generation (u64) || authority_revision (LP) ||
///   computer (LP) || incarnation (LP) || account (LP) || manager (LP) ||
///   scope_ops (count u32 + each op as 1 byte) ||
///   desktop_generation (u64) || nonce (32) || issued_at (u64) || expires_at (u64)
pub fn canonical_signing_bytes(fields: &CanonicalFields) -> Result<Vec<u8>, CanonicalError> {
    fields.validate_structure()?;
    let mut out = Vec::with_capacity(512);

    out.extend_from_slice(DOMAIN_TAG);
    out.push(0x00);

    encode_lp(&mut out, fields.schema.as_bytes(), "schema")?;
    encode_lp(&mut out, fields.deployment.as_bytes(), "deployment")?;
    encode_u64(&mut out, fields.issuer_generation);
    encode_lp(
        &mut out,
        fields.authority_revision.as_str().as_bytes(),
        "authority_revision",
    )?;
    encode_lp(&mut out, fields.computer.as_bytes(), "computer")?;
    encode_lp(&mut out, fields.incarnation.as_bytes(), "incarnation")?;
    encode_lp(&mut out, fields.account.as_bytes(), "account")?;
    encode_lp(&mut out, fields.manager.as_bytes(), "manager")?;

    let ops = fields.action_scope.operations();
    out.extend_from_slice(&(ops.len() as u32).to_be_bytes());
    for op in ops {
        out.push(op.opcode());
    }

    encode_u64(&mut out, fields.desktop_generation.as_u64());
    encode_32(&mut out, fields.session_nonce.as_bytes());
    encode_u64(&mut out, fields.issued_at.as_u64());
    encode_u64(&mut out, fields.expires_at.as_u64());

    if out.len() > MAX_CANONICAL_BODY {
        return Err(CanonicalError::BodyTooLarge(out.len()));
    }
    Ok(out)
}

fn decode_lp<'a>(
    data: &'a [u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<&'a str, CanonicalError> {
    if *pos + 4 > data.len() {
        return Err(CanonicalError::Truncated(field));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[*pos..*pos + 4]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    *pos += 4;
    if len == 0 {
        return Err(CanonicalError::EmptyField(field));
    }
    if *pos + len > data.len() {
        return Err(CanonicalError::Truncated(field));
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len]).map_err(|_| CanonicalError::InvalidId)?;
    *pos += len;
    Ok(s)
}

fn decode_u64(data: &[u8], pos: &mut usize, field: &'static str) -> Result<u64, CanonicalError> {
    if *pos + 8 > data.len() {
        return Err(CanonicalError::Truncated(field));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_be_bytes(buf))
}

fn decode_32(
    data: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<[u8; 32], CanonicalError> {
    if *pos + 32 > data.len() {
        return Err(CanonicalError::Truncated(field));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    Ok(buf)
}

/// Decode canonical bytes back to fields (for verification).
/// Safe on every truncation; never panics.
pub fn canonical_decode(data: &[u8]) -> Result<CanonicalFields, CanonicalError> {
    if data.len() > MAX_CANONICAL_BODY {
        return Err(CanonicalError::BodyTooLarge(data.len()));
    }
    if data.len() < DOMAIN_TAG.len() + 1 {
        return Err(CanonicalError::Truncated("domain"));
    }
    if &data[..DOMAIN_TAG.len()] != DOMAIN_TAG {
        return Err(CanonicalError::EmptyField("domain_mismatch"));
    }
    let mut pos = DOMAIN_TAG.len();
    if data[pos] != 0x00 {
        return Err(CanonicalError::EmptyField("separator"));
    }
    pos += 1;

    let schema = decode_lp(data, &mut pos, "schema")?;
    let deployment_str = decode_lp(data, &mut pos, "deployment")?;
    let issuer_generation = decode_u64(data, &mut pos, "issuer_generation")?;
    let authority_rev_str = decode_lp(data, &mut pos, "authority_revision")?;
    let computer_str = decode_lp(data, &mut pos, "computer")?;
    let incarnation_str = decode_lp(data, &mut pos, "incarnation")?;
    let account_str = decode_lp(data, &mut pos, "account")?;
    let manager_str = decode_lp(data, &mut pos, "manager")?;

    if pos + 4 > data.len() {
        return Err(CanonicalError::Truncated("scope_count"));
    }
    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(&data[pos..pos + 4]);
    let op_count = u32::from_be_bytes(count_bytes) as usize;
    pos += 4;
    if op_count == 0 {
        return Err(CanonicalError::EmptyField("scope_empty"));
    }
    if op_count > MAX_SCOPE_OPS {
        return Err(CanonicalError::FieldTooLong("scope_ops"));
    }
    let mut ops = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        if pos >= data.len() {
            return Err(CanonicalError::Truncated("scope_op"));
        }
        let opcode = data[pos];
        pos += 1;
        let op = Operation::from_opcode(opcode).ok_or(CanonicalError::UnknownOp(opcode))?;
        if ops.contains(&op) {
            return Err(CanonicalError::DuplicateOp);
        }
        ops.push(op);
    }

    let desktop_raw = decode_u64(data, &mut pos, "desktop_generation")?;
    let nonce_bytes = decode_32(data, &mut pos, "nonce")?;
    let issued_raw = decode_u64(data, &mut pos, "issued_at")?;
    let expires_raw = decode_u64(data, &mut pos, "expires_at")?;

    if pos != data.len() {
        return Err(CanonicalError::TrailingBytes);
    }

    let fields = CanonicalFields {
        schema: schema.to_string(),
        deployment: DeploymentId::new(deployment_str).map_err(|_| CanonicalError::InvalidId)?,
        issuer_generation,
        authority_revision: AuthorityRevision::new(authority_rev_str)
            .map_err(|_| CanonicalError::InvalidId)?,
        computer: ComputerId::new(computer_str).map_err(|_| CanonicalError::InvalidId)?,
        incarnation: IncarnationId::new(incarnation_str).map_err(|_| CanonicalError::InvalidId)?,
        account: AccountId::new(account_str).map_err(|_| CanonicalError::InvalidId)?,
        manager: ManagerId::new(manager_str).map_err(|_| CanonicalError::InvalidId)?,
        action_scope: ActionScope::new(ops).map_err(|_| CanonicalError::DuplicateOp)?,
        desktop_generation: DesktopGeneration::new(desktop_raw)
            .map_err(|_| CanonicalError::ZeroValue("desktop_generation"))?,
        session_nonce: Nonce::new(nonce_bytes).map_err(|_| CanonicalError::ZeroValue("nonce"))?,
        issued_at: TimestampMs::new(issued_raw).map_err(|_| CanonicalError::InvalidTimeBounds)?,
        expires_at: TimestampMs::new(expires_raw).map_err(|_| CanonicalError::InvalidTimeBounds)?,
    };
    fields.validate_structure()?;
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fields() -> CanonicalFields {
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
    fn encode_decode_roundtrip() {
        let fields = sample_fields();
        let bytes = canonical_signing_bytes(&fields).unwrap();
        let decoded = canonical_decode(&bytes).unwrap();
        assert_eq!(decoded.schema, fields.schema);
        assert_eq!(decoded.deployment, fields.deployment);
        assert_eq!(decoded.computer, fields.computer);
        assert_eq!(decoded.account, fields.account);
        assert_eq!(decoded.manager, fields.manager);
        assert_eq!(decoded.action_scope, fields.action_scope);
        assert_eq!(decoded.session_nonce, fields.session_nonce);
        assert_eq!(decoded.desktop_generation, fields.desktop_generation);
    }

    #[test]
    fn deterministic_encoding() {
        let b1 = canonical_signing_bytes(&sample_fields()).unwrap();
        let b2 = canonical_signing_bytes(&sample_fields()).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn different_fields_produce_different_bytes() {
        let f1 = sample_fields();
        let mut f2 = sample_fields();
        f2.desktop_generation = DesktopGeneration::new(4).unwrap();
        assert_ne!(
            canonical_signing_bytes(&f1).unwrap(),
            canonical_signing_bytes(&f2).unwrap()
        );
    }

    #[test]
    fn domain_tag_present() {
        let bytes = canonical_signing_bytes(&sample_fields()).unwrap();
        assert!(bytes.starts_with(DOMAIN_TAG));
    }

    #[test]
    fn every_truncation_is_safe() {
        let bytes = canonical_signing_bytes(&sample_fields()).unwrap();
        for n in 0..bytes.len() {
            let _ = canonical_decode(&bytes[..n]);
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = canonical_signing_bytes(&sample_fields()).unwrap();
        bytes.push(0);
        assert_eq!(canonical_decode(&bytes), Err(CanonicalError::TrailingBytes));
    }

    #[test]
    fn unknown_op_rejected() {
        let bytes = canonical_signing_bytes(&sample_fields()).unwrap();
        // Layout tail: desktop(8) + nonce(32) + issued(8) + expires(8) = 56.
        // Single observe opcode sits immediately before that tail.
        let mut bad = bytes.clone();
        let op_idx = bad.len() - 56 - 1;
        bad[op_idx] = 0x7F;
        assert_eq!(canonical_decode(&bad), Err(CanonicalError::UnknownOp(0x7F)));
    }

    #[test]
    fn duplicate_op_rejected() {
        let mut fields = sample_fields();
        fields.action_scope = ActionScope::new([Operation::Observe, Operation::Control]).unwrap();
        let mut bytes = canonical_signing_bytes(&fields).unwrap();
        // Replace control opcode with observe to forge a duplicate
        if let Some(idx) = bytes
            .iter()
            .rposition(|&b| b == Operation::Control.opcode())
        {
            bytes[idx] = Operation::Observe.opcode();
        }
        assert_eq!(canonical_decode(&bytes), Err(CanonicalError::DuplicateOp));
    }

    #[test]
    fn zero_values_rejected() {
        let mut fields = sample_fields();
        fields.desktop_generation =
            DesktopGeneration::new(0).unwrap_or(DesktopGeneration::new(1).unwrap());
        // Force zero via encode path is blocked by type; check structure on crafted
        fields.issuer_generation = 0;
        assert_eq!(
            fields.validate_structure(),
            Err(CanonicalError::ZeroValue("issuer_generation"))
        );

        let mut zero_nonce = sample_fields();
        // Direct structure check for zero nonce is prevented by Nonce::new;
        // non-positive duration is checked here.
        zero_nonce.expires_at = TimestampMs::new(1000).unwrap();
        assert_eq!(
            zero_nonce.validate_structure(),
            Err(CanonicalError::InvalidTimeBounds)
        );
    }

    #[test]
    fn oversized_body_rejected() {
        let mut bytes = canonical_signing_bytes(&sample_fields()).unwrap();
        bytes.resize(MAX_CANONICAL_BODY + 1, 0);
        assert!(matches!(
            canonical_decode(&bytes),
            Err(CanonicalError::BodyTooLarge(_))
        ));
    }

    #[test]
    fn empty_and_bad_ids_rejected_at_decode() {
        let fields = sample_fields();
        let bytes = canonical_signing_bytes(&fields).unwrap();
        // Corrupt a length to zero: schema length is first LP after domain+sep
        let mut bad = bytes.clone();
        let lp_start = DOMAIN_TAG.len() + 1;
        bad[lp_start + 3] = 0; // low byte of u32 length → 0
        assert!(canonical_decode(&bad).is_err());
    }
}
