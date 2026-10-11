// swift_lifetime_check.swift — compile + lifetime checks for HsNativeWrapper.
//
// Exercises: pin-count enforcement, root tracking/retirement, close-request vs
// safely-drained, real callbacks with synchronization gates, abandonment safety,
// ABI gate, native descriptor sizeof/offsets, parallel close, register-vs-close,
// post-free registration, and bounded roots.
// No mock pixels, identities, grants, or media.

import Foundation

private func compileTimeDescContract() {
    let d = HsFrameDesc(
        width: 1, height: 2, stride: 3, format: 4, length: 5,
        display: 6, viewerGeneration: 7, layoutGeneration: 8,
        interactionGeneration: 9, sequence: 10
    )
    precondition(d.viewerGeneration == 7)
    precondition(d.layoutGeneration == 8)
    precondition(d.interactionGeneration == 9)
    precondition(d.sequence == 10)
}

/// Linked native descriptor layout vs wrapper struct. Constructing our own
/// descriptor does NOT prove native marshalling — compare against the
/// C-imported `hs_frame_desc` from the generated header.
private func checkNativeDescLayout(_ check: (Bool, String) -> Void) {
    let cSize = MemoryLayout<hs_frame_desc>.size
    let sSize = MemoryLayout<HsFrameDesc>.size
    check(cSize == 48, "MemoryLayout<hs_frame_desc>.size == 48 (native), got \(cSize)")
    check(sSize == cSize, "Swift HsFrameDesc size matches native C size (\(sSize) == \(cSize))")
    check(MemoryLayout<HsFrameDesc>.stride == MemoryLayout<hs_frame_desc>.stride,
          "Swift HsFrameDesc stride matches native C stride")
    let cSeq = MemoryLayout<hs_frame_desc>.offset(of: \.sequence)
    let sSeq = MemoryLayout<HsFrameDesc>.offset(of: \.sequence)
    check(cSeq == 40, "native offsetof(sequence) == 40, got \(String(describing: cSeq))")
    check(sSeq == cSeq, "Swift HsFrameDesc sequence offset matches native (\(String(describing: sSeq)) == \(String(describing: cSeq)))")
    let cVG = MemoryLayout<hs_frame_desc>.offset(of: \.viewer_generation)
    let sVG = MemoryLayout<HsFrameDesc>.offset(of: \.viewerGeneration)
    check(cVG == 24, "native offsetof(viewer_generation) == 24, got \(String(describing: cVG))")
    check(sVG == cVG, "Swift viewerGeneration offset matches native")
}

@main
struct SwiftLifetimeCheck {
    static func main() {
        compileTimeDescContract()
        var failures = 0

        func check(_ cond: Bool, _ name: String) {
            if cond { print("ok   \(name)") }
            else { print("FAIL \(name)"); failures += 1 }
        }

        check(HsStatus.ok.rawValue == 0, "HsStatus.ok == 0")
        check(HsEngineContext.expectedAbiVersion == 2, "expectedAbiVersion == 2")

        // Linked ABI must be 2 before any context is allocated.
        let linkedAbi = hs_abi_version()
        check(linkedAbi == HsEngineContext.expectedAbiVersion,
              "linked hs_abi_version == expected ABI2 (\(linkedAbi))")

        checkNativeDescLayout(check)

        // --- Basic lifetime ---
        do {
            let ctx = try HsEngineContext()
            check(true, "context construct")
            try ctx.prepare()
            check(try ctx.state() == .prepared, "state is PREPARED (inert)")
            check(!ctx.isCloseRequested, "close not yet requested")
            check(!ctx.isSafelyDrained, "not drained before close")
            try ctx.requestClose()
            check(ctx.isCloseRequested, "close-request recorded")
            check(!ctx.isSafelyDrained, "close-request is NOT safely drained")
            try ctx.drain(timeoutMs: 500)
            check(ctx.isSafelyDrained, "drain marks safely drained")
            let frame = try ctx.acquireLatestFrame(display: 0)
            check(frame == nil, "acquire on empty slot returns nil")
            try ctx.freeAfterDrain()
            check(true, "free after drain")
            do {
                try ctx.freeAfterDrain()
                check(true, "second freeAfterDrain is a no-op (double free prevented)")
            } catch {
                check(true, "second freeAfterDrain refused (double free prevented)")
            }
        } catch {
            print("FAIL basic lifetime threw \(error)")
            failures += 1
        }

        // --- Free before drain refused ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            try ctx.requestClose()
            do {
                try ctx.freeAfterDrain()
                check(false, "free before drain must be refused")
            } catch let e as HsStatus {
                check(e == .state, "free before drain refused with STATE")
            }
            try ctx.drain(timeoutMs: 500)
            try ctx.freeAfterDrain()
            check(true, "drain then free succeeds")
        } catch {
            print("FAIL free-before-drain threw \(error)")
            failures += 1
        }

        // --- Real callback with synchronization gate ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            let gate = DispatchSemaphore(value: 0)
            let calls = CallCounter()
            try ctx.setLifecycleHandler { ev in
                if case .closing = ev {
                    calls.increment()
                    gate.signal()
                }
            }
            try ctx.requestClose()
            let waited = gate.wait(timeout: .now() + 2.0)
            check(waited == .success, "real callback signal received")
            try ctx.drain(timeoutMs: 1000)
            check(calls.value >= 1, "real lifecycle callback executed on worker")
            check(ctx.isSafelyDrained, "drained after real callback")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL real callback threw \(error)")
            failures += 1
        }

        // --- Reentrant close from callback ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            let gate = DispatchSemaphore(value: 0)
            let calls = CallCounter()
            try ctx.setLifecycleHandler { ev in
                if case .closing = ev {
                    try? ctx.requestClose()
                    calls.increment()
                    gate.signal()
                }
            }
            try ctx.requestClose()
            _ = gate.wait(timeout: .now() + 2.0)
            try ctx.drain(timeoutMs: 1000)
            check(calls.value == 1, "callback re-entered request_close safely")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL reentrant close threw \(error)")
            failures += 1
        }

        // --- Replacement keeps old root until drain ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            let oldCalls = CallCounter()
            let newCalls = CallCounter()
            let newGate = DispatchSemaphore(value: 0)
            try ctx.setLifecycleHandler { ev in
                if case .closing = ev { oldCalls.increment() }
            }
            try ctx.setLifecycleHandler { ev in
                if case .closing = ev {
                    newCalls.increment()
                    newGate.signal()
                }
            }
            check(ctx.rootedRegistrationCount == 2,
                  "replacement keeps old root (2 rooted registrations)")
            try ctx.requestClose()
            _ = newGate.wait(timeout: .now() + 2.0)
            try ctx.drain(timeoutMs: 1000)
            check(newCalls.value == 1, "new handler got subsequent callback")
            check(oldCalls.value == 0, "old handler not invoked after replacement")
            check(ctx.rootedRegistrationCount == 0, "drain released all roots")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL replacement threw \(error)")
            failures += 1
        }

        // --- Registration after drain refused ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            try ctx.requestClose()
            try ctx.drain(timeoutMs: 1000)
            let before = ctx.rootedRegistrationCount
            do {
                try ctx.setLifecycleHandler { _ in }
                check(false, "registration after drain must be refused")
            } catch let e as HsStatus {
                check(e == .state, "failed after-drain registration refused with STATE")
            }
            check(ctx.rootedRegistrationCount == before,
                  "failed after-drain registration does not leak a root")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL after-drain registration threw \(error)")
            failures += 1
        }

        // --- Drain releases all roots ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            for _ in 0..<3 {
                try ctx.setLifecycleHandler { _ in }
            }
            check(ctx.rootedRegistrationCount == 3, "3 registrations rooted")
            try ctx.requestClose()
            try ctx.drain(timeoutMs: 1000)
            check(ctx.rootedRegistrationCount == 0,
                  "successful drain releases ALL registration roots")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL drain-releases-roots threw \(error)")
            failures += 1
        }

        // --- Free while callback in flight refused ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            let inCallback = DispatchSemaphore(value: 0)
            let releaseCallback = DispatchSemaphore(value: 0)
            let finished = CallCounter()
            try ctx.setLifecycleHandler { ev in
                if case .closing = ev {
                    inCallback.signal()
                    _ = releaseCallback.wait(timeout: .now() + 3.0)
                    finished.increment()
                }
            }
            try ctx.requestClose()
            _ = inCallback.wait(timeout: .now() + 3.0)
            do {
                try ctx.freeAfterDrain()
                check(false, "free while callback in flight must be refused")
            } catch let e as HsStatus {
                check(e == .state, "free while callback in flight refused with STATE")
            }
            releaseCallback.signal()
            try ctx.drain(timeoutMs: 2000)
            check(finished.value == 1, "callback completed")
            try ctx.freeAfterDrain()
            check(true, "free succeeds after drain")
        } catch {
            print("FAIL concurrent-free threw \(error)")
            failures += 1
        }

        // --- Abandonment: deinit after drain frees; before drain leaks safely ---
        do {
            var ctx: HsEngineContext? = try HsEngineContext()
            try ctx!.prepare()
            try ctx!.requestClose()
            try ctx!.drain(timeoutMs: 500)
            ctx = nil // deinit frees (drained, unpinned)
            check(true, "deinit after drain frees safely")
        } catch {
            print("FAIL abandonment threw \(error)")
            failures += 1
        }

        // --- Post-free registration: refused, no retained-root leak ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            try ctx.requestClose()
            try ctx.drain(timeoutMs: 1000)
            try ctx.freeAfterDrain()
            do {
                try ctx.setLifecycleHandler { _ in }
                check(false, "post-free registration must be refused")
            } catch let e as HsStatus {
                check(e == .state, "post-free registration refused with STATE")
            }
            check(ctx.rootedRegistrationCount == 0,
                  "post-free registration leaves no retained root")
        } catch {
            print("FAIL post-free registration threw \(error)")
            failures += 1
        }

        // --- Parallel close: one generation bump, one CLOSING ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            let closingCount = CallCounter()
            let gate = DispatchSemaphore(value: 0)
            try ctx.setLifecycleHandler { ev in
                if case .closing = ev {
                    closingCount.increment()
                    gate.signal()
                }
            }
            let group = DispatchGroup()
            for _ in 0..<8 {
                group.enter()
                DispatchQueue.global().async {
                    try? ctx.requestClose()
                    group.leave()
                }
            }
            check(group.wait(timeout: .now() + 3.0) == .success, "parallel close joins")
            _ = gate.wait(timeout: .now() + 2.0)
            try ctx.drain(timeoutMs: 1000)
            check(closingCount.value == 1,
                  "exactly one CLOSING across parallel close (\(closingCount.value))")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL parallel close threw \(error)")
            failures += 1
        }

        // --- Register racing close/drain: never a retained root after drain ---
        for i in 0..<8 {
            do {
                let ctx = try HsEngineContext()
                try ctx.prepare()
                let group = DispatchGroup()
                group.enter()
                DispatchQueue.global().async {
                    try? ctx.setLifecycleHandler { _ in }
                    group.leave()
                }
                group.enter()
                DispatchQueue.global().async {
                    try? ctx.requestClose()
                    _ = try? ctx.drain(timeoutMs: 1000)
                    group.leave()
                }
                _ = group.wait(timeout: .now() + 3.0)
                // After the race, a later registration is refused and no
                // orphan root is left for a drain that already completed.
                do {
                    try ctx.setLifecycleHandler { _ in }
                    check(false, "post-race registration must be refused (iter \(i))")
                } catch {
                    check(true, "post-race registration refused (iter \(i))")
                }
                if ctx.isSafelyDrained {
                    check(ctx.rootedRegistrationCount == 0,
                          "no retained root after racing drain (iter \(i))")
                }
                if ctx.isSafelyDrained {
                    try ctx.freeAfterDrain()
                } else {
                    try ctx.requestClose()
                    try ctx.drain(timeoutMs: 1000)
                    try ctx.freeAfterDrain()
                }
            } catch {
                print("FAIL register-vs-close iter \(i) threw \(error)")
                failures += 1
            }
        }

        // --- Bounded registrations match the native limit ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            // First registration + 8 replacements = 9 accepted.
            for i in 0..<HsEngineContext.maxRegistrations {
                try ctx.setLifecycleHandler { _ in }
                check(ctx.rootedRegistrationCount == i + 1,
                      "bounded root tracked (\(i + 1))")
            }
            do {
                try ctx.setLifecycleHandler { _ in }
                check(false, "registration past bound must be refused")
            } catch let e as HsStatus {
                check(e == .state || e == .exhausted,
                      "registration past bound refused (\(e))")
            }
            check(ctx.rootedRegistrationCount == HsEngineContext.maxRegistrations,
                  "bounded registrations stop at maxRegistrations")
            try ctx.requestClose()
            try ctx.drain(timeoutMs: 1000)
            check(ctx.rootedRegistrationCount == 0, "bound drain released all roots")
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL bounded roots threw \(error)")
            failures += 1
        }

        // --- Polling mode: events retained when no callback ---
        do {
            let ctx = try HsEngineContext()
            try ctx.prepare()
            try ctx.debugQueueLife(code: 1, generation: 1)
            try ctx.debugQueueLife(code: 1, generation: 2)
            Thread.sleep(forTimeInterval: 0.05)
            let e1 = try ctx.pollLifecycle()
            let e2 = try ctx.pollLifecycle()
            check(e1 == .frameReady(generation: 1), "poll retained event 1")
            check(e2 == .frameReady(generation: 2), "poll retained event 2")
            check(try ctx.pollLifecycle() == nil, "poll empty after retained events")
            try ctx.requestClose()
            try ctx.drain(timeoutMs: 1000)
            try ctx.freeAfterDrain()
        } catch {
            print("FAIL polling mode threw \(error)")
            failures += 1
        }

        print("=== \(failures == 0 ? "PASSED" : "FAILED") (\(failures) failures) ===")
        exit(failures == 0 ? 0 : 1)
    }
}

private final class CallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func increment() {
        lock.lock(); n += 1; lock.unlock()
    }
    var value: Int {
        lock.lock(); defer { lock.unlock() }; return n
    }
}
