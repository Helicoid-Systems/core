//! Decoder for the native WebRTC product-channel binding.
//!
//! This validates the transport tuple exported by `webrtc-native`. It does
//! not authenticate the peer, prove that bytes came from the native bridge,
//! issue product authority, or authorize capture or input.

/// Domain tag including the C++ bridge's null terminator.
pub const WEBRTC_CHANNEL_BINDING_DOMAIN: &[u8] = b"HS-WEBRTC-DTLS-SCTP-V1\0";
/// Only data-channel label included in the product transport binding.
pub const WEBRTC_PRODUCT_CHANNEL_LABEL: &[u8] = b"hs-product";
/// Exact encoded binding size for the fixed label and two SHA-256 digests.
pub const WEBRTC_CHANNEL_BINDING_LEN: usize =
    WEBRTC_CHANNEL_BINDING_DOMAIN.len() + 2 + WEBRTC_PRODUCT_CHANNEL_LABEL.len() + 2 + 64;

/// Failure to parse the native WebRTC channel-binding tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcChannelBindingError {
    WrongLength { expected: usize, actual: usize },
    WrongDomain,
    WrongProductLabel,
    ReservedStreamId { stream_id: u16 },
    NonCanonicalCertificateOrder,
}

/// Parsed transport binding for one negotiated `hs-product` SCTP channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcChannelBinding {
    stream_id: u16,
    certificate_digests: [[u8; 32]; 2],
}

impl WebRtcChannelBinding {
    /// Build the canonical tuple from the stream ID and both leaf digests.
    /// Digest order is normalized so both WebRTC peers encode identical bytes.
    pub fn new(
        stream_id: u16,
        local_digest: [u8; 32],
        remote_digest: [u8; 32],
    ) -> Result<Self, WebRtcChannelBindingError> {
        if stream_id == u16::MAX {
            return Err(WebRtcChannelBindingError::ReservedStreamId { stream_id });
        }
        let certificate_digests = if local_digest <= remote_digest {
            [local_digest, remote_digest]
        } else {
            [remote_digest, local_digest]
        };
        Ok(Self {
            stream_id,
            certificate_digests,
        })
    }

    /// Parse and validate the exact fixed-width native transport tuple.
    pub fn decode(bytes: &[u8]) -> Result<Self, WebRtcChannelBindingError> {
        if bytes.len() != WEBRTC_CHANNEL_BINDING_LEN {
            return Err(WebRtcChannelBindingError::WrongLength {
                expected: WEBRTC_CHANNEL_BINDING_LEN,
                actual: bytes.len(),
            });
        }

        let domain_end = WEBRTC_CHANNEL_BINDING_DOMAIN.len();
        if bytes[..domain_end] != *WEBRTC_CHANNEL_BINDING_DOMAIN {
            return Err(WebRtcChannelBindingError::WrongDomain);
        }

        let label_length_offset = domain_end;
        let label_length =
            u16::from_be_bytes([bytes[label_length_offset], bytes[label_length_offset + 1]]);
        if usize::from(label_length) != WEBRTC_PRODUCT_CHANNEL_LABEL.len() {
            return Err(WebRtcChannelBindingError::WrongProductLabel);
        }

        let label_start = label_length_offset + 2;
        let label_end = label_start + WEBRTC_PRODUCT_CHANNEL_LABEL.len();
        if bytes[label_start..label_end] != *WEBRTC_PRODUCT_CHANNEL_LABEL {
            return Err(WebRtcChannelBindingError::WrongProductLabel);
        }

        let stream_id = u16::from_be_bytes([bytes[label_end], bytes[label_end + 1]]);
        if stream_id == u16::MAX {
            return Err(WebRtcChannelBindingError::ReservedStreamId { stream_id });
        }
        let digest_start = label_end + 2;
        let mut first = [0u8; 32];
        first.copy_from_slice(&bytes[digest_start..digest_start + 32]);
        let mut second = [0u8; 32];
        second.copy_from_slice(&bytes[digest_start + 32..digest_start + 64]);
        if first > second {
            return Err(WebRtcChannelBindingError::NonCanonicalCertificateOrder);
        }

        Ok(Self {
            stream_id,
            certificate_digests: [first, second],
        })
    }

    /// Encode the canonical tuple expected by the native bridge contract.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(WEBRTC_CHANNEL_BINDING_LEN);
        bytes.extend_from_slice(WEBRTC_CHANNEL_BINDING_DOMAIN);
        bytes.extend_from_slice(&(WEBRTC_PRODUCT_CHANNEL_LABEL.len() as u16).to_be_bytes());
        bytes.extend_from_slice(WEBRTC_PRODUCT_CHANNEL_LABEL);
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());
        bytes.extend_from_slice(&self.certificate_digests[0]);
        bytes.extend_from_slice(&self.certificate_digests[1]);
        bytes
    }

    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }

    pub const fn certificate_digests(&self) -> &[[u8; 32]; 2] {
        &self.certificate_digests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_matches_the_native_tuple_layout() {
        let binding = WebRtcChannelBinding::new(0x1234, [0x22; 32], [0x11; 32])
            .expect("non-reserved SCTP stream ID is valid");
        let mut expected = b"HS-WEBRTC-DTLS-SCTP-V1\0".to_vec();
        expected.extend_from_slice(&10u16.to_be_bytes());
        expected.extend_from_slice(b"hs-product");
        expected.extend_from_slice(&[0x12, 0x34]);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 32]);

        assert_eq!(binding.encode(), expected);
        let decoded = WebRtcChannelBinding::decode(&expected).expect("native tuple decodes");
        assert_eq!(decoded, binding);
        assert_eq!(decoded.stream_id(), 0x1234);
    }

    #[test]
    fn opposite_peer_order_produces_identical_bytes() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let from_a = WebRtcChannelBinding::new(7, first, second)
            .expect("non-reserved SCTP stream ID is valid");
        let from_b = WebRtcChannelBinding::new(7, second, first)
            .expect("non-reserved SCTP stream ID is valid");
        assert_eq!(from_a.encode(), from_b.encode());
    }

    #[test]
    fn decoder_rejects_wrong_size_domain_label_and_digest_order() {
        let encoded = WebRtcChannelBinding::new(4, [0x11; 32], [0x22; 32])
            .expect("non-reserved SCTP stream ID is valid")
            .encode();
        assert!(matches!(
            WebRtcChannelBinding::decode(&encoded[..encoded.len() - 1]),
            Err(WebRtcChannelBindingError::WrongLength { .. })
        ));

        let mut wrong_domain = encoded.clone();
        wrong_domain[0] ^= 1;
        assert_eq!(
            WebRtcChannelBinding::decode(&wrong_domain),
            Err(WebRtcChannelBindingError::WrongDomain)
        );

        let mut wrong_label = encoded.clone();
        let label_offset = WEBRTC_CHANNEL_BINDING_DOMAIN.len() + 2;
        wrong_label[label_offset] ^= 1;
        assert_eq!(
            WebRtcChannelBinding::decode(&wrong_label),
            Err(WebRtcChannelBindingError::WrongProductLabel)
        );

        let digest_offset = label_offset + WEBRTC_PRODUCT_CHANNEL_LABEL.len() + 2;
        let mut noncanonical = encoded;
        noncanonical[digest_offset..digest_offset + 32].fill(0x33);
        noncanonical[digest_offset + 32..digest_offset + 64].fill(0x11);
        assert_eq!(
            WebRtcChannelBinding::decode(&noncanonical),
            Err(WebRtcChannelBindingError::NonCanonicalCertificateOrder)
        );
    }

    #[test]
    fn rejects_reserved_sctp_stream_id() {
        assert_eq!(
            WebRtcChannelBinding::new(u16::MAX, [0x11; 32], [0x22; 32]),
            Err(WebRtcChannelBindingError::ReservedStreamId {
                stream_id: u16::MAX,
            })
        );

        let mut encoded = WebRtcChannelBinding::new(u16::MAX - 1, [0x11; 32], [0x22; 32])
            .expect("65534 is a valid SCTP stream ID")
            .encode();
        assert_eq!(
            WebRtcChannelBinding::decode(&encoded)
                .expect("65534 decodes")
                .stream_id(),
            u16::MAX - 1
        );

        let stream_id_offset =
            WEBRTC_CHANNEL_BINDING_DOMAIN.len() + 2 + WEBRTC_PRODUCT_CHANNEL_LABEL.len();
        encoded[stream_id_offset..stream_id_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            WebRtcChannelBinding::decode(&encoded),
            Err(WebRtcChannelBindingError::ReservedStreamId {
                stream_id: u16::MAX,
            })
        );
    }
}
