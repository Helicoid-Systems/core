// HsWebRtcWrapper.swift -- Swift bindings for the E01 ABI-3 subset.
// Covers only the exports implemented by hs_webrtc_bridge.cpp.
// Opaque handles are registry tokens; never dereference them.

import Foundation

public enum HsWebRtcStatus: UInt32 {
    case ok = 0
    case invalid = 1
    case null = 2
    case state = 3
    case panic = 4
    case exhausted = 5
    case unavailable = 6
    case internalError = 7
    case bounds = 8
    case timeout = 9
    case handshake = 10
}

public struct HsWebRtcEngine {
    public static let abiVersion: UInt32 = 3
    private var raw: OpaquePointer?

    public init() throws {
        // Gate construction on the linked ABI version before any allocation.
        let linked = hs_abi_version()
        guard linked == HsWebRtcEngine.abiVersion else {
            throw HsWebRtcError.status(.invalid)
        }
        var p: OpaquePointer? = nil
        let st = hs_engine_init(&p)
        guard st == 0, let handle = p else {
            throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError)
        }
        self.raw = handle
    }

    public mutating func shutdown() -> HsWebRtcStatus {
        guard let h = raw else { return .null }
        let st = hs_engine_shutdown(h)
        raw = nil
        return HsWebRtcStatus(rawValue: st) ?? .internalError
    }

    public func drain(timeoutMs: UInt32) -> HsWebRtcStatus {
        guard let h = raw else { return .null }
        return HsWebRtcStatus(rawValue: hs_engine_drain(h, timeoutMs)) ?? .internalError
    }

    public static func engineVersion() -> String {
        String(cString: hs_engine_version())
    }

    public static func capabilities() throws -> UInt32 {
        var mask: UInt32 = 0
        let st = hs_engine_capabilities(&mask)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return mask
    }

    public func createPeer() throws -> HsWebRtcPeer {
        guard let h = raw else { throw HsWebRtcError.status(.null) }
        var p: OpaquePointer? = nil
        let st = hs_peer_create(h, &p)
        guard st == 0, let ph = p else {
            throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError)
        }
        return HsWebRtcPeer(handle: ph)
    }

    /// Relay-only TLS/TCP peer with exact LAB certificate trust.
    /// Credentials are never logged. No insecure cert policy option exists.
    /// Exclusive-pin build mode is required; otherwise the engine returns
    /// unavailable instead of offering a weaker pin.
    ///
    /// Trust is mandatory and exactly one of: PEM, or a 32-byte SHA-256 DER
    /// digest. Wrong-length SHA and dual PEM+SHA are rejected before any
    /// native call (the native ABI would read past a short buffer).
    public func createRelayPeer(
        host: String, port: UInt32, username: String, password: String,
        trustPem: String? = nil, trustSha256: [UInt8]? = nil
    ) throws -> HsWebRtcPeer {
        guard let h = raw else { throw HsWebRtcError.status(.null) }

        let hasPem = trustPem.map { !$0.isEmpty } ?? false
        let hasSha = trustSha256 != nil
        // Exactly one trust mode. No trust is fail-closed; dual mode unsupported.
        if hasPem == hasSha {
            throw HsWebRtcError.status(.invalid)
        }
        if let sha = trustSha256, sha.count != 32 {
            // Native reads HS_MAX_TURN_TRUST_SHA256 (32) bytes; never pass a
            // shorter allocation with len forced to 32.
            throw HsWebRtcError.status(.bounds)
        }

        // Bound UTF-8 lengths before UInt32 narrowing to native field widths.
        let hostLen = host.utf8.count
        let userLen = username.utf8.count
        let passLen = password.utf8.count
        guard hostLen > 0, hostLen <= Int(HS_MAX_TURN_HOST_BYTES),
              userLen > 0, userLen <= Int(HS_MAX_TURN_USER_BYTES),
              passLen > 0, passLen <= Int(HS_MAX_TURN_PASS_BYTES) else {
            throw HsWebRtcError.status(.bounds)
        }
        let pemLen = hasPem ? (trustPem?.utf8.count ?? 0) : 0
        guard !hasPem || (pemLen > 0 && pemLen <= Int(HS_MAX_TURN_TRUST_PEM_BYTES)) else {
            throw HsWebRtcError.status(.bounds)
        }

        var p: OpaquePointer? = nil
        let st = host.withCString { hp in
            username.withCString { up in
                password.withCString { pp in
                    func make(_ pem: UnsafePointer<CChar>?, _ sha: UnsafePointer<UInt8>?,
                              _ shaLen: UInt32) -> UInt32 {
                        var cfg = hs_turn_tls_config(
                            struct_size: UInt32(MemoryLayout<hs_turn_tls_config>.size),
                            version: 1,
                            host: hp, host_len: UInt32(hostLen),
                            port: port,
                            username: up, username_len: UInt32(userLen),
                            password: pp, password_len: UInt32(passLen),
                            trust_pem: pem, trust_pem_len: UInt32(pemLen),
                            trust_sha256: sha, trust_sha256_len: shaLen
                        )
                        return hs_peer_create_relay(h, &cfg, &p)
                    }
                    if let sha = trustSha256 {
                        return sha.withUnsafeBufferPointer { sbuf in
                            make(nil, sbuf.baseAddress, UInt32(sha.count))
                        }
                    }
                    if hasPem, let pem = trustPem {
                        return pem.withCString { rawPem in
                            make(rawPem, nil, 0)
                        }
                    }
                    return make(nil, nil, 0)
                }
            }
        }
        guard st == 0, let ph = p else {
            throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError)
        }
        return HsWebRtcPeer(handle: ph)
    }
}

public struct HsWebRtcScreenFrame {
    public let width: UInt32
    public let height: UInt32
    public let bgra: Data
}

public struct HsWebRtcPeer {
    let handle: OpaquePointer

    public func prepareVideo(role: UInt32) throws {
        guard role == HS_VIDEO_ROLE_SEND_ONLY || role == HS_VIDEO_ROLE_RECEIVE_ONLY else {
            throw HsWebRtcError.status(.invalid)
        }
        let st = hs_peer_video_prepare(handle, role)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func beginObservation(channelBinding: Data, leaseMs: UInt32) throws {
        guard !channelBinding.isEmpty,
              channelBinding.count <= Int(HS_MAX_CHANNEL_BINDING_BYTES),
              leaseMs > 0, leaseMs <= HS_MAX_OBSERVATION_LEASE_MS else {
            throw HsWebRtcError.status(.bounds)
        }
        let st = channelBinding.withUnsafeBytes { raw in
            hs_admission_begin(handle, raw.bindMemory(to: UInt8.self).baseAddress,
                               UInt32(channelBinding.count), leaseMs)
        }
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func endObservation() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_admission_end(handle)) ?? .internalError
    }

    public func beginCapture(expectedGeneration: UInt32) -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_capture_begin(handle, expectedGeneration)) ?? .internalError
    }

    public func endCapture() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_capture_end(handle)) ?? .internalError
    }

    public func pushBgraFrame(_ bgra: Data, width: UInt32, height: UInt32,
                              stride: UInt32) throws {
        guard width > 0, width <= HS_MAX_SCREEN_FRAME_WIDTH,
              height > 0, height <= HS_MAX_SCREEN_FRAME_HEIGHT,
              stride >= width * 4,
              UInt64(stride) * UInt64(height) == UInt64(bgra.count),
              bgra.count <= Int(HS_MAX_SCREEN_FRAME_WIDTH) *
                  Int(HS_MAX_SCREEN_FRAME_HEIGHT) * 4 else {
            throw HsWebRtcError.status(.bounds)
        }
        let st = bgra.withUnsafeBytes { raw in
            hs_peer_video_frame_push(handle, raw.bindMemory(to: UInt8.self).baseAddress,
                                     UInt32(bgra.count), width, height, stride)
        }
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func acquireScreenFrame() throws -> HsWebRtcScreenFrame {
        let maxFrameBytes = Int(HS_MAX_SCREEN_FRAME_WIDTH) *
            Int(HS_MAX_SCREEN_FRAME_HEIGHT) * 4
        var pixels = [UInt8](repeating: 0, count: maxFrameBytes)
        var width: UInt32 = 0
        var height: UInt32 = 0
        let st = hs_media_frame_acquire(handle, UInt32(pixels.count), &pixels, &width, &height)
        guard st == 0 else {
            pixels.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) }
            throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError)
        }
        guard width > 0, width <= HS_MAX_SCREEN_FRAME_WIDTH,
              height > 0, height <= HS_MAX_SCREEN_FRAME_HEIGHT else {
            pixels.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) }
            throw HsWebRtcError.status(.bounds)
        }
        let byteCount = Int(width) * Int(height) * 4
        let frame = HsWebRtcScreenFrame(width: width, height: height,
                                        bgra: Data(pixels[0..<byteCount]))
        pixels.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) }
        return frame
    }

    public func close() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_peer_close(handle)) ?? .internalError
    }

    /// Free after close. After a successful retiring drain the handle is
    /// already gone (returns null). A timed-out drain retains the peer and
    /// free returns timeout until a later proven drain/free.
    public func free() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_peer_free(handle)) ?? .internalError
    }

    public func drain(timeoutMs: UInt32) -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_peer_drain(handle, timeoutMs)) ?? .internalError
    }

    public func generation() throws -> UInt32 {
        var g: UInt32 = 0
        let st = hs_peer_generation(handle, &g)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return g
    }

    public func localCertificate() throws -> Data {
        var buf = [UInt8](repeating: 0, count: 8192)
        var len: UInt32 = 0
        let st = hs_peer_local_cert_export(handle, &buf, UInt32(buf.count), &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return Data(buf[0..<Int(len)])
    }

    public func setExpectedCertificate(_ pem: Data) throws {
        let st = pem.withUnsafeBytes { raw in
            hs_peer_expected_cert_set(handle, raw.bindMemory(to: CChar.self).baseAddress, pem.count)
        }
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func acquireVerifiedChannel() throws -> HsWebRtcVerifiedChannel {
        var p: OpaquePointer? = nil
        let st = hs_verified_channel_acquire(handle, &p)
        guard st == 0, let vh = p else {
            throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError)
        }
        return HsWebRtcVerifiedChannel(handle: vh)
    }

    public func state() throws -> UInt32 {
        var s: UInt32 = 0
        let st = hs_peer_state(handle, &s)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return s
    }

    public func createProductChannel() throws {
        let label = Array(HS_PRODUCT_CHANNEL_LABEL.utf8CString)
        let st = hs_channel_create(handle, label, label.count - 1)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func createOffer() throws -> String {
        var buf = [CChar](repeating: 0, count: 65536)
        var len: UInt = 0
        let st = hs_peer_create_offer(handle, &buf, buf.count, &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return String(cString: buf)
    }

    public func createAnswer() throws -> String {
        var buf = [CChar](repeating: 0, count: 65536)
        var len: UInt = 0
        let st = hs_peer_create_answer(handle, &buf, buf.count, &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return String(cString: buf)
    }

    public func setLocalIgnored(_ sdp: String) -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_peer_set_local(handle, sdp, sdp.utf8.count)) ?? .internalError
    }

    public func setRemote(type: String, sdp: String) throws {
        let st = hs_peer_set_remote(handle, type, type.utf8.count, sdp, sdp.utf8.count)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func addIce(_ sdp: String) throws {
        let st = hs_peer_add_ice(handle, sdp, sdp.utf8.count)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func pollIce() throws -> String {
        var buf = [CChar](repeating: 0, count: 65536)
        var len: UInt = 0
        let st = hs_peer_poll_ice(handle, &buf, buf.count, &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return String(cString: buf)
    }

    public func send(_ data: Data) throws {
        let st = data.withUnsafeBytes { raw in
            hs_channel_send(handle, raw.bindMemory(to: UInt8.self).baseAddress, UInt32(data.count))
        }
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
    }

    public func pollMessage() throws -> Data {
        var buf = [UInt8](repeating: 0, count: 4096)
        var len: UInt32 = 0
        let st = hs_channel_poll(handle, &buf, UInt32(buf.count), &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return Data(buf[0..<Int(len)])
    }

    public func closeChannel() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_channel_close(handle)) ?? .internalError
    }

    /// Selected candidate/transport evidence from native stats (lab).
    /// Decodes only the checked returned length as UTF-8. Native export writes
    /// exact bytes and may fill the entire cap without a NUL terminator.
    public func selectedTransportJson() throws -> String {
        let cap = Int(HS_MAX_SELECTED_JSON_BYTES)
        var buf = [UInt8](repeating: 0, count: cap)
        var len: UInt = 0
        let st = hs_peer_selected_transport_export(handle, &buf, cap, &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        guard len > 0, len <= UInt(cap) else {
            throw HsWebRtcError.status(.bounds)
        }
        guard let s = String(bytes: buf[0..<Int(len)], encoding: .utf8) else {
            throw HsWebRtcError.status(.invalid)
        }
        return s
    }

    /// Causal TLS trust diagnostics from REAL verifier callbacks.
    /// Independent of selected-route existence. Not identity/admission.
    public func turnTrustDiagnostics() throws -> (calls: UInt32, accepts: UInt32, rejects: UInt32) {
        var calls: UInt32 = 0
        var accepts: UInt32 = 0
        var rejects: UInt32 = 0
        let st = hs_peer_turn_trust_diagnostics(handle, &calls, &accepts, &rejects)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return (calls, accepts, rejects)
    }

}

public struct HsWebRtcVerifiedChannel {
    let handle: OpaquePointer

    public func exportCertificate() throws -> Data {
        var buf = [UInt8](repeating: 0, count: 8192)
        var len: UInt32 = 0
        let st = hs_verified_channel_export(handle, &buf, UInt32(buf.count), &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return Data(buf[0..<Int(len)])
    }

    public func exportChannelBinding() throws -> Data {
        var buf = [UInt8](repeating: 0, count: 128)
        var len: UInt32 = 0
        let st = hs_verified_channel_binding_export(handle, &buf, UInt32(buf.count), &len)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return Data(buf[0..<Int(len)])
    }

    public func generation() throws -> UInt32 {
        var g: UInt32 = 0
        let st = hs_verified_channel_generation(handle, &g)
        guard st == 0 else { throw HsWebRtcError.status(HsWebRtcStatus(rawValue: st) ?? .internalError) }
        return g
    }

    public func isValid() -> Bool {
        var v: UInt32 = 0
        guard hs_verified_channel_valid(handle, &v) == 0 else { return false }
        return v == 1
    }

    public func release() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_verified_channel_release(handle)) ?? .internalError
    }
}

public enum HsWebRtcError: Error {
    case status(HsWebRtcStatus)
}
