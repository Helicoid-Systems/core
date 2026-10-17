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

            // --- relay wrapper malformed-boundary regressions (no network) ---
            // Native ABI size is what the wrapper puts in struct_size.
            // A mismatch is caught by native INVALID on the correct-32 case.
            let abiSize = MemoryLayout<hs_turn_tls_config>.size
            check(abiSize > 0 && abiSize <= 256,
                  "hs_turn_tls_config ABI size bounded (got \(abiSize))")

            let host = "localhost"
            let user = "1273168000:hs-lab"
            let pass = "dGVzdA=="
            let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

            // Empty / absent trust denied before native.
            do {
                _ = try engine.createRelayPeer(host: host, port: 5349, username: user, password: pass)
                check(false, "empty trust rejected")
            } catch HsWebRtcError.status(let st) {
                check(st == .invalid || st == .bounds, "empty trust rejected")
            }

            // Dual PEM+SHA must not silently prefer SHA.
            do {
                _ = try engine.createRelayPeer(host: host, port: 5349, username: user, password: pass,
                                               trustPem: pem, trustSha256: [UInt8](repeating: 1, count: 32))
                check(false, "dual trust rejected")
            } catch HsWebRtcError.status(let st) {
                check(st == .invalid, "dual trust rejected")
            }

            // Wrong-length SHA arrays rejected BEFORE native (OOB prevention).
            for n in [0, 1, 31, 33] {
                do {
                    _ = try engine.createRelayPeer(host: host, port: 5349, username: user, password: pass,
                                                   trustSha256: [UInt8](repeating: 7, count: n))
                    check(false, "sha len \(n) rejected")
                } catch HsWebRtcError.status(let st) {
                    check(st == .bounds || st == .invalid, "sha len \(n) rejected")
                }
            }

            // Correct 32-byte SHA config passes wrapper validation into native.
            // Construct-only: an enabled exclusive-pin build must create the
            // peer object successfully without a network round-trip.
            do {
                let rp = try engine.createRelayPeer(
                    host: host, port: 5349, username: user, password: pass,
                    trustSha256: [UInt8](repeating: 0xAB, count: 32))
                check(true, "correct 32-byte sha wrapper accepted")
                _ = rp.close()
                _ = rp.drain(timeoutMs: 500)
                _ = rp.free()
            } catch HsWebRtcError.status(let st) {
                // An enabled relay capability must construct successfully.
                // A build that omits it must report unavailable explicitly.
                check(mask & UInt32(HS_CAP_TURN_TLS) == 0 && st == .unavailable,
                      "correct 32-byte sha unavailable only when capability absent (st=\(st))")
            }

            // selectedTransportJson without a selected route must throw safely
            // (length/UTF8 decode only runs on a successful export).
            let peer2 = try engine.createPeer()
            do {
                _ = try peer2.selectedTransportJson()
                check(false, "selectedTransportJson without route throws")
            } catch {
                check(true, "selectedTransportJson without route throws safely")
            }
            _ = peer2.close()
            _ = peer2.drain(timeoutMs: 500)
            _ = peer2.free()

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
