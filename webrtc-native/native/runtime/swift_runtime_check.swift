// Swift runtime check against libhs_webrtc_shared (durable repo source).
// Constructs HsWebRtcEngine/Peer wrappers AND exercises the C ABI seam.
// Compiles together with wrappers/HsWebRtcWrapper.swift.
import Foundation

@main
struct SwiftRuntimeCheck {
    static var failures = 0
    static var checks = 0

    static func check(_ cond: Bool, _ name: String) {
        checks += 1
        if cond { print("ok   \(name)") } else { failures += 1; print("FAIL \(name)") }
    }

    static func main() {
        do {
            // --- C ABI seam (exact calling convention) ---
            let linked = hs_abi_version()
            check(linked == HsWebRtcEngine.abiVersion, "swift hs_abi_version matches wrapper constant")

            let ver = String(cString: hs_engine_version())
            check(ver.hasPrefix("hs-webrtc-native/"), "swift engine_version prefix")

            var mask: UInt32 = 0
            check(hs_engine_capabilities(&mask) == 0, "swift capabilities ok")
            check(mask & 0x10 == 0, "swift cap capture unset")
            check(mask & 0x20 == 0, "swift cap admission unset")
            check(mask & 0x40 == 0, "swift cap media unset")

            // --- actual wrapper object lifecycle ---
            var engine = try HsWebRtcEngine()
            let peer = try engine.createPeer()
            let gen = try peer.generation()
            check(gen != 0, "wrapper peer generation")

            let cert = try peer.localCertificate()
            check(cert.count > 0, "wrapper local certificate")

            // Forged handle fails closed at the C seam.
            let forged = OpaquePointer(bitPattern: 0x1234)
            var fv: UInt32 = 1
            check(hs_verified_channel_valid(forged, &fv) != 0 && fv == 0, "forged handle rejected")

            // Wrapper close / drain / free ownership path.
            check(peer.close() == HsWebRtcStatus.ok, "wrapper peer close")
            let dr = peer.drain(timeoutMs: 1000)
            check(dr == .ok || dr == .timeout || dr == .state || dr == .null, "wrapper peer drain honest")
            let fr = peer.free()
            check(fr == .ok || fr == .timeout || fr == .state || fr == .null, "wrapper peer free safe")

            let sd = engine.shutdown()
            check(sd == .ok || sd == .timeout, "wrapper engine shutdown")
        } catch {
            checks += 1
            failures += 1
            print("FAIL uncaught \(error)")
        }
        print("")
        print("\(checks) checks, \(failures) failures")
        if failures != 0 { exit(1) }
    }
}
