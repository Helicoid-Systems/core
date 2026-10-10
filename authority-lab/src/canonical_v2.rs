//! Canonical v2 signing representation with domain separation.
//!
//! Versioned bounded canonical messages for distributed admission proof.
//! Deterministic byte layout for Ed25519 signatures. All fields are
//! length-prefixed or fixed-width. Domain tag + schema version prefix
//! every signed message.
//!
//! Decoding is total: every truncation is a clean error, never a panic.
//! The entire body is length-bounded before parsing.
//!
//! ## v2 adds over v1
//!
//! - issuer_public_key bound directly into the signed representation
//! - approved_account_key and approved_manager_key (32-byte public keys)
//! - endpoint_key and endpoint_incarnation
//! - boot_id, worker_id
//! - display_generation (zero = not applicable)
//! - operation_intent, interaction_generation
//! - policy_revision
//! - channel_binding (exact, not proof of transport)

use crate::types::*;

/// Domain separation tag for v2 admission credentials.
pub const V2_DOMAIN_TAG: &[u8] = b"HAL-AUTH-ADMISSION-V2";

/// Canonical v2 schema version.
pub const V2_SCHEMA_VERSION: &str = "v2";

/// Hard bound on the entire v2 canonical body.
pub const MAX_V2_CANONICAL_BODY: usize = 4096;

/// Maximum operations in one action scope.
pub const MAX_V2_SCOPE_OPS: usize = 3;

/// Maximum channel binding length.
pub const MAX_V2_CHANNEL_BINDING_LEN: usize = 128;

/// Canonical v2 error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalV2Error {
    #[error("field too long for canonical encoding: {0}")]
    FieldTooLong(&'static str),
    #[error("empty field in canonical encoding: {0}")]
    EmptyField(&'static str),
    #[error("body exceeds bound: {0} > {MAX_V2_CANONICAL_BODY}")]
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
    #[error("zero public key for {0}")]
    ZeroPublicKey(&'static str),
    #[error("channel binding too long: {0}")]
    ChannelBindingTooLong(usize),
    #[error("channel binding is zero")]
    ChannelBindingZero,
}

/// Full v2 canonical fields for distributed admission signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalV2Fields {
    pub schema: String,
    pub deployment: DeploymentId,
    pub issuer_generation: u64,
    /// Issuer public key bound into the signed representation.
    pub issuer_public_key: [u8; 32],
    /// Approved account public key.
    pub approved_account_key: [u8; 32],
    /// Approved manager public key.
    pub approved_manager_key: [u8; 32],
    /// Endpoint public key.
    pub endpoint_key: EndpointKey,
    pub endpoint_incarnation: EndpointIncarnation,
    pub boot_id: BootId,
    pub worker_id: WorkerId,
    pub computer: ComputerId,
    pub incarnation: IncarnationId,
    pub desktop_generation: DesktopGeneration,
    /// Zero = not applicable (display/layout generation).
    pub display_generation: u64,
    pub operation: Operation,
    pub operation_intent: OperationIntent,
    pub interaction_generation: InteractionGeneration,
    pub policy_revision: PolicyRevision,
    pub authority_revision: AuthorityRevision,
    /// Exact channel binding value (not proof of transport).
    pub channel_binding: Vec<u8>,
    pub session_nonce: Nonce,
    pub issued_at: TimestampMs,
    pub expires_at: TimestampMs,
}

impl CanonicalV2Fields {
    /// Structural checks applied on every public issuance/admission path.
    pub fn validate_structure(&self) -> Result<(), CanonicalV2Error> {
        if self.issuer_generation == 0 {
            return Err(CanonicalV2Error::ZeroValue("issuer_generation"));
        }
        if self.issuer_public_key == [0u8; 32] {
            return Err(CanonicalV2Error::ZeroPublicKey("issuer_public_key"));
        }
        if self.approved_account_key == [0u8; 32] {
            return Err(CanonicalV2Error::ZeroPublicKey("approved_account_key"));
        }
        if self.approved_manager_key == [0u8; 32] {
            return Err(CanonicalV2Error::ZeroPublicKey("approved_manager_key"));
        }
        if self.desktop_generation.as_u64() == 0 {
            return Err(CanonicalV2Error::ZeroValue("desktop_generation"));
        }
        if self.interaction_generation.as_u64() == 0 {
            return Err(CanonicalV2Error::ZeroValue("interaction_generation"));
        }
        if self.session_nonce.as_bytes() == &[0u8; 32] {
            return Err(CanonicalV2Error::ZeroValue("nonce"));
        }
        if self.issued_at.to_i64().is_err() || self.expires_at.to_i64().is_err() {
            return Err(CanonicalV2Error::InvalidTimeBounds);
        }
        if self.expires_at.as_u64() <= self.issued_at.as_u64() {
            return Err(CanonicalV2Error::InvalidTimeBounds);
        }
        if self.channel_binding.is_empty() {
            return Err(CanonicalV2Error::EmptyField("channel_binding"));
        }
        if self.channel_binding.len() > MAX_V2_CHANNEL_BINDING_LEN {
            return Err(CanonicalV2Error::ChannelBindingTooLong(
                self.channel_binding.len(),
            ));
        }
        if self.channel_binding.iter().all(|&b| b == 0) {
            return Err(CanonicalV2Error::ChannelBindingZero);
        }
        Ok(())
    }
}

// --- Encode helpers ---

fn encode_lp(out: &mut Vec<u8>, data: &[u8], field: &'static str) -> Result<(), CanonicalV2Error> {
    if data.is_empty() {
        return Err(CanonicalV2Error::EmptyField(field));
    }
    if data.len() > u32::MAX as usize {
        return Err(CanonicalV2Error::FieldTooLong(field));
    }
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn encode_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn encode_32(out: &mut Vec<u8>, v: &[u8; 32]) {
    out.extend_from_slice(v);
}

/// Build the v2 canonical signing bytes.
///
/// Layout:
///   V2_DOMAIN_TAG (fixed) || 0x00 ||
///   schema (LP) || deployment (LP) ||
///   issuer_generation (u64) || issuer_public_key (32) ||
///   approved_account_key (32) || approved_manager_key (32) ||
///   endpoint_key (32) || endpoint_incarnation (LP) ||
///   boot_id (LP) || worker_id (LP) ||
///   computer (LP) || incarnation (LP) ||
///   desktop_generation (u64) || display_generation (u64) ||
///   operation (1) || operation_intent (LP) ||
///   interaction_generation (u64) || policy_revision (LP) ||
///   authority_revision (LP) || channel_binding (LP) ||
///   nonce (32) || issued_at (u64) || expires_at (u64)
pub fn canonical_v2_signing_bytes(fields: &CanonicalV2Fields) -> Result<Vec<u8>, CanonicalV2Error> {
    fields.validate_structure()?;
    let mut out = Vec::with_capacity(1024);

    out.extend_from_slice(V2_DOMAIN_TAG);
    out.push(0x00);

    encode_lp(&mut out, fields.schema.as_bytes(), "schema")?;
    encode_lp(&mut out, fields.deployment.as_bytes(), "deployment")?;
    encode_u64(&mut out, fields.issuer_generation);
    encode_32(&mut out, &fields.issuer_public_key);
    encode_32(&mut out, &fields.approved_account_key);
    encode_32(&mut out, &fields.approved_manager_key);
    encode_32(&mut out, fields.endpoint_key.as_bytes());
    encode_lp(
        &mut out,
        fields.endpoint_incarnation.as_bytes(),
        "endpoint_incarnation",
    )?;
    encode_lp(&mut out, fields.boot_id.as_bytes(), "boot_id")?;
    encode_lp(&mut out, fields.worker_id.as_bytes(), "worker_id")?;
    encode_lp(&mut out, fields.computer.as_bytes(), "computer")?;
    encode_lp(&mut out, fields.incarnation.as_bytes(), "incarnation")?;
    encode_u64(&mut out, fields.desktop_generation.as_u64());
    encode_u64(&mut out, fields.display_generation);
    out.push(fields.operation.opcode());
    encode_lp(
        &mut out,
        fields.operation_intent.as_bytes(),
        "operation_intent",
    )?;
    encode_u64(&mut out, fields.interaction_generation.as_u64());
    encode_lp(
        &mut out,
        fields.policy_revision.as_bytes(),
        "policy_revision",
    )?;
    encode_lp(
        &mut out,
        fields.authority_revision.as_bytes(),
        "authority_revision",
    )?;
    encode_lp(&mut out, &fields.channel_binding, "channel_binding")?;
    encode_32(&mut out, fields.session_nonce.as_bytes());
    encode_u64(&mut out, fields.issued_at.as_u64());
    encode_u64(&mut out, fields.expires_at.as_u64());

    if out.len() > MAX_V2_CANONICAL_BODY {
        return Err(CanonicalV2Error::BodyTooLarge(out.len()));
    }
    Ok(out)
}

// --- Decode helpers ---

fn decode_lp<'a>(
    data: &'a [u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<&'a [u8], CanonicalV2Error> {
    if *pos + 4 > data.len() {
        return Err(CanonicalV2Error::Truncated(field));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[*pos..*pos + 4]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    *pos += 4;
    if len == 0 {
        return Err(CanonicalV2Error::EmptyField(field));
    }
    if *pos + len > data.len() {
        return Err(CanonicalV2Error::Truncated(field));
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

fn decode_lp_str<'a>(
    data: &'a [u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<&'a str, CanonicalV2Error> {
    let bytes = decode_lp(data, pos, field)?;
    std::str::from_utf8(bytes).map_err(|_| CanonicalV2Error::InvalidId)
}

fn decode_u64(data: &[u8], pos: &mut usize, field: &'static str) -> Result<u64, CanonicalV2Error> {
    if *pos + 8 > data.len() {
        return Err(CanonicalV2Error::Truncated(field));
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
) -> Result<[u8; 32], CanonicalV2Error> {
    if *pos + 32 > data.len() {
        return Err(CanonicalV2Error::Truncated(field));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    Ok(buf)
}

/// Decode v2 canonical bytes back to fields. Safe on every truncation;
/// never panics.
pub fn canonical_v2_decode(data: &[u8]) -> Result<CanonicalV2Fields, CanonicalV2Error> {
    if data.len() > MAX_V2_CANONICAL_BODY {
        return Err(CanonicalV2Error::BodyTooLarge(data.len()));
    }
    if data.len() < V2_DOMAIN_TAG.len() + 1 {
        return Err(CanonicalV2Error::Truncated("domain"));
    }
    if &data[..V2_DOMAIN_TAG.len()] != V2_DOMAIN_TAG {
        return Err(CanonicalV2Error::EmptyField("domain_mismatch"));
    }
    let mut pos = V2_DOMAIN_TAG.len();
    if data[pos] != 0x00 {
        return Err(CanonicalV2Error::EmptyField("separator"));
    }
    pos += 1;

    let schema = decode_lp_str(data, &mut pos, "schema")?;
    let deployment_str = decode_lp_str(data, &mut pos, "deployment")?;
    let issuer_generation = decode_u64(data, &mut pos, "issuer_generation")?;
    let issuer_pk = decode_32(data, &mut pos, "issuer_public_key")?;
    let account_key = decode_32(data, &mut pos, "approved_account_key")?;
    let manager_key = decode_32(data, &mut pos, "approved_manager_key")?;
    let endpoint_key_bytes = decode_32(data, &mut pos, "endpoint_key")?;
    let endpoint_inc_str = decode_lp_str(data, &mut pos, "endpoint_incarnation")?;
    let boot_id_str = decode_lp_str(data, &mut pos, "boot_id")?;
    let worker_id_str = decode_lp_str(data, &mut pos, "worker_id")?;
    let computer_str = decode_lp_str(data, &mut pos, "computer")?;
    let incarnation_str = decode_lp_str(data, &mut pos, "incarnation")?;
    let desktop_raw = decode_u64(data, &mut pos, "desktop_generation")?;
    let display_raw = decode_u64(data, &mut pos, "display_generation")?;

    if pos >= data.len() {
        return Err(CanonicalV2Error::Truncated("operation"));
    }
    let opcode = data[pos];
    pos += 1;
    let operation = Operation::from_opcode(opcode).ok_or(CanonicalV2Error::UnknownOp(opcode))?;

    let intent_str = decode_lp_str(data, &mut pos, "operation_intent")?;
    let interaction_raw = decode_u64(data, &mut pos, "interaction_generation")?;
    let policy_str = decode_lp_str(data, &mut pos, "policy_revision")?;
    let authority_rev_str = decode_lp_str(data, &mut pos, "authority_revision")?;
    let channel_bytes = decode_lp(data, &mut pos, "channel_binding")?;
    let nonce_bytes = decode_32(data, &mut pos, "nonce")?;
    let issued_raw = decode_u64(data, &mut pos, "issued_at")?;
    let expires_raw = decode_u64(data, &mut pos, "expires_at")?;

    if pos != data.len() {
        return Err(CanonicalV2Error::TrailingBytes);
    }

    let fields = CanonicalV2Fields {
        schema: schema.to_string(),
        deployment: DeploymentId::new(deployment_str).map_err(|_| CanonicalV2Error::InvalidId)?,
        issuer_generation,
        issuer_public_key: issuer_pk,
        approved_account_key: account_key,
        approved_manager_key: manager_key,
        endpoint_key: EndpointKey::new(endpoint_key_bytes)
            .map_err(|_| CanonicalV2Error::ZeroPublicKey("endpoint_key"))?,
        endpoint_incarnation: EndpointIncarnation::new(endpoint_inc_str)
            .map_err(|_| CanonicalV2Error::InvalidId)?,
        boot_id: BootId::new(boot_id_str).map_err(|_| CanonicalV2Error::InvalidId)?,
        worker_id: WorkerId::new(worker_id_str).map_err(|_| CanonicalV2Error::InvalidId)?,
        computer: ComputerId::new(computer_str).map_err(|_| CanonicalV2Error::InvalidId)?,
        incarnation: IncarnationId::new(incarnation_str)
            .map_err(|_| CanonicalV2Error::InvalidId)?,
        desktop_generation: DesktopGeneration::new(desktop_raw)
            .map_err(|_| CanonicalV2Error::ZeroValue("desktop_generation"))?,
        display_generation: display_raw,
        operation,
        operation_intent: OperationIntent::new(intent_str)
            .map_err(|_| CanonicalV2Error::InvalidId)?,
        interaction_generation: InteractionGeneration::new(interaction_raw)
            .map_err(|_| CanonicalV2Error::ZeroValue("interaction_generation"))?,
        policy_revision: PolicyRevision::new(policy_str)
            .map_err(|_| CanonicalV2Error::InvalidId)?,
        authority_revision: AuthorityRevision::new(authority_rev_str)
            .map_err(|_| CanonicalV2Error::InvalidId)?,
        channel_binding: channel_bytes.to_vec(),
        session_nonce: Nonce::new(nonce_bytes).map_err(|_| CanonicalV2Error::ZeroValue("nonce"))?,
        issued_at: TimestampMs::new(issued_raw).map_err(|_| CanonicalV2Error::InvalidTimeBounds)?,
        expires_at: TimestampMs::new(expires_raw)
            .map_err(|_| CanonicalV2Error::InvalidTimeBounds)?,
    };
    fields.validate_structure()?;
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v2_fields() -> CanonicalV2Fields {
        CanonicalV2Fields {
            schema: V2_SCHEMA_VERSION.to_string(),
            deployment: DeploymentId::new("deploy-1").unwrap(),
            issuer_generation: 1,
            issuer_public_key: [0xAAu8; 32], // fixed for determinism
            approved_account_key: [2u8; 32],
            approved_manager_key: [3u8; 32],
            endpoint_key: EndpointKey::new([4u8; 32]).unwrap(),
            endpoint_incarnation: EndpointIncarnation::new("ep-inc-1").unwrap(),
            boot_id: BootId::new("boot-1").unwrap(),
            worker_id: WorkerId::new("worker-1").unwrap(),
            computer: ComputerId::new("room7-a03").unwrap(),
            incarnation: IncarnationId::new("inc-abc").unwrap(),
            desktop_generation: DesktopGeneration::new(3).unwrap(),
            display_generation: 2,
            operation: Operation::Observe,
            operation_intent: OperationIntent::new("view-stream").unwrap(),
            interaction_generation: InteractionGeneration::new(1).unwrap(),
            policy_revision: PolicyRevision::new("policy-2026").unwrap(),
            authority_revision: AuthorityRevision::new("rev-1").unwrap(),
            channel_binding: b"channel-v2-binding".to_vec(),
            session_nonce: Nonce::new([1u8; 32]).unwrap(),
            issued_at: TimestampMs::new(1000).unwrap(),
            expires_at: TimestampMs::new(2000).unwrap(),
        }
    }

    #[test]
    fn v2_encode_decode_roundtrip() {
        let fields = sample_v2_fields();
        let bytes = canonical_v2_signing_bytes(&fields).unwrap();
        let decoded = canonical_v2_decode(&bytes).unwrap();
        assert_eq!(decoded.schema, fields.schema);
        assert_eq!(decoded.deployment, fields.deployment);
        assert_eq!(decoded.issuer_public_key, fields.issuer_public_key);
        assert_eq!(decoded.approved_account_key, fields.approved_account_key);
        assert_eq!(decoded.approved_manager_key, fields.approved_manager_key);
        assert_eq!(decoded.endpoint_key, fields.endpoint_key);
        assert_eq!(decoded.endpoint_incarnation, fields.endpoint_incarnation);
        assert_eq!(decoded.boot_id, fields.boot_id);
        assert_eq!(decoded.worker_id, fields.worker_id);
        assert_eq!(decoded.computer, fields.computer);
        assert_eq!(decoded.incarnation, fields.incarnation);
        assert_eq!(decoded.desktop_generation, fields.desktop_generation);
        assert_eq!(decoded.display_generation, fields.display_generation);
        assert_eq!(decoded.operation, fields.operation);
        assert_eq!(decoded.operation_intent, fields.operation_intent);
        assert_eq!(
            decoded.interaction_generation,
            fields.interaction_generation
        );
        assert_eq!(decoded.policy_revision, fields.policy_revision);
        assert_eq!(decoded.authority_revision, fields.authority_revision);
        assert_eq!(decoded.channel_binding, fields.channel_binding);
        assert_eq!(decoded.session_nonce, fields.session_nonce);
        assert_eq!(decoded.issued_at, fields.issued_at);
        assert_eq!(decoded.expires_at, fields.expires_at);
    }

    #[test]
    fn v2_deterministic_encoding() {
        let b1 = canonical_v2_signing_bytes(&sample_v2_fields()).unwrap();
        let b2 = canonical_v2_signing_bytes(&sample_v2_fields()).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn v2_domain_tag_present() {
        let bytes = canonical_v2_signing_bytes(&sample_v2_fields()).unwrap();
        assert!(bytes.starts_with(V2_DOMAIN_TAG));
    }

    #[test]
    fn v2_different_fields_produce_different_bytes() {
        let f1 = sample_v2_fields();
        let mut f2 = sample_v2_fields();
        f2.display_generation = 99;
        assert_ne!(
            canonical_v2_signing_bytes(&f1).unwrap(),
            canonical_v2_signing_bytes(&f2).unwrap()
        );
    }

    #[test]
    fn v2_every_truncation_is_safe() {
        let bytes = canonical_v2_signing_bytes(&sample_v2_fields()).unwrap();
        for n in 0..bytes.len() {
            let _ = canonical_v2_decode(&bytes[..n]);
        }
    }

    #[test]
    fn v2_trailing_bytes_rejected() {
        let mut bytes = canonical_v2_signing_bytes(&sample_v2_fields()).unwrap();
        bytes.push(0);
        assert_eq!(
            canonical_v2_decode(&bytes),
            Err(CanonicalV2Error::TrailingBytes)
        );
    }

    #[test]
    fn v2_unknown_op_rejected() {
        // Compute the operation byte position by comparing bytes with two
        // different operation values; the differing byte is the opcode.
        let mut f_observe = sample_v2_fields();
        f_observe.operation = Operation::Observe;
        let b_observe = canonical_v2_signing_bytes(&f_observe).unwrap();
        let mut f_control = sample_v2_fields();
        f_control.operation = Operation::Control;
        let b_control = canonical_v2_signing_bytes(&f_control).unwrap();
        let op_idx = b_observe
            .iter()
            .zip(b_control.iter())
            .position(|(a, b)| a != b)
            .expect("operation bytes differ");
        let mut bad = b_observe;
        bad[op_idx] = 0x7F;
        assert_eq!(
            canonical_v2_decode(&bad),
            Err(CanonicalV2Error::UnknownOp(0x7F))
        );
    }

    #[test]
    fn v2_zero_public_keys_rejected() {
        let mut fields = sample_v2_fields();
        fields.issuer_public_key = [0u8; 32];
        assert!(canonical_v2_signing_bytes(&fields).is_err());

        fields = sample_v2_fields();
        fields.approved_account_key = [0u8; 32];
        assert!(canonical_v2_signing_bytes(&fields).is_err());

        fields = sample_v2_fields();
        fields.approved_manager_key = [0u8; 32];
        assert!(canonical_v2_signing_bytes(&fields).is_err());
    }

    #[test]
    fn v2_zero_endpoint_key_rejected() {
        let mut fields = sample_v2_fields();
        fields.endpoint_key =
            EndpointKey::new([0u8; 32]).unwrap_or(EndpointKey::new([1u8; 32]).unwrap());
        // Can't construct zero EndpointKey, so test the error path directly
        assert!(EndpointKey::new([0u8; 32]).is_err());
    }

    #[test]
    fn v2_zero_display_generation_allowed() {
        let mut fields = sample_v2_fields();
        fields.display_generation = 0; // zero = not applicable
        let bytes = canonical_v2_signing_bytes(&fields).unwrap();
        let decoded = canonical_v2_decode(&bytes).unwrap();
        assert_eq!(decoded.display_generation, 0);
    }

    #[test]
    fn v2_channel_binding_rejects_empty_and_zero() {
        let mut fields = sample_v2_fields();
        fields.channel_binding = vec![];
        assert!(canonical_v2_signing_bytes(&fields).is_err());

        fields = sample_v2_fields();
        fields.channel_binding = vec![0u8; 8];
        assert!(canonical_v2_signing_bytes(&fields).is_err());
    }

    #[test]
    fn v2_oversized_body_rejected() {
        let mut bytes = canonical_v2_signing_bytes(&sample_v2_fields()).unwrap();
        bytes.resize(MAX_V2_CANONICAL_BODY + 1, 0);
        assert!(matches!(
            canonical_v2_decode(&bytes),
            Err(CanonicalV2Error::BodyTooLarge(_))
        ));
    }
}
