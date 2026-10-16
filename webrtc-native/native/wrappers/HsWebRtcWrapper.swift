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
}

public struct HsWebRtcPeer {
    let handle: OpaquePointer

    public func close() -> HsWebRtcStatus {
        HsWebRtcStatus(rawValue: hs_peer_close(handle)) ?? .internalError
    }

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
