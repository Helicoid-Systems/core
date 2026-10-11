// HsNativeWrapper.swift — Helicoid RD02 Swift wrapper over the generated C ABI.
//
// GENERATED-CONTRACT: consumes `native/hs_native.h` exactly. Never guess a
// layout. Run `scripts/check-wrapper-contract.py` after any header change.
//
// Scope (lab only):
//   - owns one `hs_engine_ctx *` and prevents double free
//   - marshals the exact `hs_frame_desc` (including the distinct
//     layout/interaction admission fences and the separate viewer/cancel
//     generation)
//   - roots every lifecycle registration until proven drain (bounded)
//   - distinguishes close-request (non-blocking) from safely drained
//   - no mock pixels, identities, grants, or media in normal construction
//
// Prepared means inert. Connect/observation/channel-binding stay unavailable
// until a real authenticated channel and sealed HS endpoint admission exist.
// This wrapper is not an authorization surface.
//
// Concurrency: `HsEngineContext` serialises all state under one NSLock and
// uses a pin counter so `freeAfterDrain` refuses while any native call is in
// flight. Locks are never held across `hs_viewer_drain` or a callback.

import Foundation

/// Status codes from `hs_native.h`.
public enum HsStatus: UInt32, Error, Sendable {
    case ok = 0
    case invalid = 1
    case null = 2
    case state = 3
    case panic = 4
    case exhausted = 5
    case unavailable = 6
    case `internal` = 7
    case bounds = 8
    case timeout = 9
    case handshake = 10

    init(raw: UInt32) {
        self = HsStatus(rawValue: raw) ?? .internal
    }
}

/// Context lifecycle states from `hs_native.h`.
public enum HsSessionState: UInt32, Sendable {
    case created = 0
    case prepared = 1
    case closing = 2
    case closed = 3
}

/// Exact `hs_frame_desc` layout from the generated header.
/// Field order and widths must match `native/hs_native.h`.
public struct HsFrameDesc: Sendable, Equatable {
    public var width: UInt32
    public var height: UInt32
    public var stride: UInt32
    public var format: UInt32
    public var length: UInt32
    public var display: UInt32
    /// Context/cancellation fence. Separate from admission fences.
    public var viewerGeneration: UInt32
    /// Frame-admission fence: layout revision (nonzero, bounded).
    public var layoutGeneration: UInt32
    /// Frame-admission fence: interaction generation (nonzero, bounded).
    public var interactionGeneration: UInt32
    public var sequence: UInt64

    public init(
        width: UInt32 = 0, height: UInt32 = 0, stride: UInt32 = 0,
        format: UInt32 = 0, length: UInt32 = 0, display: UInt32 = 0,
        viewerGeneration: UInt32 = 0, layoutGeneration: UInt32 = 0,
        interactionGeneration: UInt32 = 0, sequence: UInt64 = 0
    ) {
        self.width = width
        self.height = height
        self.stride = stride
        self.format = format
        self.length = length
        self.display = display
        self.viewerGeneration = viewerGeneration
        self.layoutGeneration = layoutGeneration
        self.interactionGeneration = interactionGeneration
        self.sequence = sequence
    }
}

/// Lifecycle event delivered on the engine delivery worker.
/// Never assume a UI thread; hop to MainActor yourself.
public enum HsLifecycleEvent: Sendable, Equatable {
    case frameReady(generation: UInt32)
    case closing(generation: UInt32)
    case drained(generation: UInt32)
    case unknown(code: UInt32, generation: UInt32)

    init(code: UInt32, generation: UInt32) {
        switch code {
        case 1: self = .frameReady(generation: generation)
        case 2: self = .closing(generation: generation)
        case 3: self = .drained(generation: generation)
        default: self = .unknown(code: code, generation: generation)
        }
    }
}

/// Owned frame handle. Release is explicit and exactly-once.
/// The pixel pointer is valid only until `close()`.
public final class HsFrameHandle: @unchecked Sendable {
    private var ptr: OpaquePointer?
    public let desc: HsFrameDesc
    private let lock = NSLock()
    private var released = false

    init?(ptr: OpaquePointer?, desc: HsFrameDesc) {
        guard let ptr else { return nil }
        self.ptr = ptr
        self.desc = desc
    }

    deinit {
        releaseIfHeld()
    }

    /// Borrow the immutable pixel buffer. Valid until `close()`.
    /// The handle is kept alive for the duration of `body`.
    public func withPixels<T>(_ body: (UnsafeRawPointer, UInt32) throws -> T) rethrows -> T? {
        lock.lock()
        defer { lock.unlock() }
        guard let ptr, !released else { return nil }
        var outPtr: UnsafePointer<UInt8>?
        var outLen: UInt32 = 0
        let st = hs_frame_pixels(ptr, &outPtr, &outLen)
        guard st == 0, let outPtr else { return nil }
        return try body(UnsafeRawPointer(outPtr), outLen)
    }

    /// Exact allocator release. Idempotent; double free is prevented here.
    public func close() {
        releaseIfHeld()
    }

    private func releaseIfHeld() {
        lock.lock()
        defer { lock.unlock() }
        guard let p = ptr, !released else { return }
        released = true
        ptr = nil
        _ = hs_frame_release(p)
    }

    public var isLive: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !released
    }
}

/// One rooted lifecycle registration. The box is retained independently of
/// wrapper reachability until drain proves the worker quiescent.
private final class CallbackRootBox: @unchecked Sendable {
    let handler: @Sendable (HsLifecycleEvent) -> Void
    init(handler: @escaping @Sendable (HsLifecycleEvent) -> Void) {
        self.handler = handler
    }
    func invoke(_ event: HsLifecycleEvent) {
        handler(event)
    }
}

/// Engine context wrapper.
///
/// Lock discipline: every mutable field is guarded by `lock`. `pinned` counts
/// in-flight native calls. `freeAfterDrain` refuses while `pinned > 0`.
/// Locks are never held across `hs_viewer_drain` or a user callback.
public final class HsEngineContext: @unchecked Sendable {
    /// ABI version this wrapper was written against (hs_native.h HS_ABI_VERSION).
    public static let expectedAbiVersion: UInt32 = 2

    private var ctx: OpaquePointer?
    private let lock = NSLock()
    private var closeRequested = false
    private var drained = false
    private var freed = false
    private var pinned = 0

    /// Every registration root, retained until drain. Bounded by the native
    /// HS_MAX_LIFE_RETIRED limit (8 replacements).
    private var roots: [Unmanaged<CallbackRootBox>] = []

    /// Maximum published registrations accepted by native: one initial
    /// registration plus `HS_MAX_LIFE_RETIRED` replacements.
    static let maxRegistrations: Int = 9

    public init() throws {
        // Validate the linked ABI BEFORE allocating a context. Loading an
        // incompatible library must fail closed rather than interpret a
        // mismatched frame descriptor.
        let abi = hs_abi_version()
        guard abi == HsEngineContext.expectedAbiVersion else {
            throw HsStatus.internal
        }
        var out: OpaquePointer?
        let st = hs_engine_ctx_new(&out)
        guard st == 0, let out else { throw HsStatus(raw: st) }
        self.ctx = out
    }

    deinit {
        // Only free when drain has completed AND no call is pinned.
        // Otherwise leak the native context (native free also refuses while
        // the worker is live) rather than UAF. Created-state (no worker) can
        // free immediately.
        lock.lock()
        let canFree = !freed && drained && pinned == 0 && ctx != nil
        let p = ctx
        if canFree {
            freed = true
            ctx = nil
        }
        let rootsToRelease = canFree ? roots : []
        if canFree { roots = [] }
        lock.unlock()
        if canFree, let p {
            _ = hs_engine_ctx_free(p)
        }
        // Release roots only when the worker is proven quiescent (drained).
        // If not drained, intentionally leak roots instead of UAF.
        for r in rootsToRelease { r.release() }
    }

    /// Construct the real inert Session. Prepared is inert, not admitted.
    public func prepare() throws {
        try withCtx { ptr in
            let st = hs_viewer_prepare(ptr)
            guard st == 0 else { throw HsStatus(raw: st) }
        }
    }

    public func state() throws -> HsSessionState {
        try withCtx { ptr in
            var raw: UInt32 = 0
            let st = hs_viewer_state(ptr, &raw)
            guard st == 0 else { throw HsStatus(raw: st) }
            return HsSessionState(rawValue: raw) ?? .created
        }
    }

    /// Non-blocking close request. Distinguishes from `isSafelyDrained`.
    /// Safe to call from inside a lifecycle callback (no lock held across).
    public func requestClose() throws {
        let ptr = try pinnedCtx()
        defer { unpinCtx() }
        let st = hs_viewer_request_close(ptr)
        if st != 0 && st != 3 { throw HsStatus(raw: st) }
        lock.lock()
        closeRequested = true
        lock.unlock()
    }

    /// Bounded async drain. On success marks safely drained and releases
    /// every registration root (worker is proven quiescent).
    /// Lock is NOT held across the native wait so callbacks may re-enter.
    public func drain(timeoutMs: UInt32) throws {
        let ptr = try pinnedCtx()
        defer { unpinCtx() }
        let st = hs_viewer_drain(ptr, timeoutMs)
        guard st == 0 else { throw HsStatus(raw: st) }
        lock.lock()
        drained = true
        let toRelease = roots
        roots = []
        lock.unlock()
        // Worker joined: release all roots.
        for r in toRelease { r.release() }
    }

    public var isSafelyDrained: Bool {
        lock.lock()
        defer { lock.unlock() }
        return drained
    }

    public var isCloseRequested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closeRequested
    }

    /// Number of retained registration roots (diagnostics).
    public var rootedRegistrationCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return roots.count
    }

    /// Acquire the latest owned frame. Returns nil when no frame is available.
    public func acquireLatestFrame(display: UInt32) throws -> HsFrameHandle? {
        try withCtx { ptr in
            var handle: OpaquePointer?
            var desc = hs_frame_desc(
                width: 0, height: 0, stride: 0, format: 0, length: 0,
                display: 0, viewer_generation: 0, layout_generation: 0,
                interaction_generation: 0, sequence: 0
            )
            let st = hs_frame_acquire_latest(ptr, display, &handle, &desc)
            if st == 3 { return nil }
            guard st == 0 else { throw HsStatus(raw: st) }
            let wrapped = HsFrameDesc(
                width: desc.width, height: desc.height, stride: desc.stride,
                format: desc.format, length: desc.length, display: desc.display,
                viewerGeneration: desc.viewer_generation,
                layoutGeneration: desc.layout_generation,
                interactionGeneration: desc.interaction_generation,
                sequence: desc.sequence
            )
            return HsFrameHandle(ptr: handle, desc: wrapped)
        }
    }

    /// Register a lifecycle handler. Runs on the engine delivery worker.
    ///
    /// The box is retained (passRetained) and tracked in `roots` until drain.
    /// Replacement retains a NEW box and keeps the old one until drain.
    /// Failed registration releases only the unpublished box, exactly once.
    /// Refused after drain or in Closing/Closed (no publication vs drain race).
    ///
    /// Lifetime: one pin covers retain + native call + root publication. A
    /// failed pin never creates a retained root. Publication that loses a
    /// drain race releases the root under proven quiescence rather than
    /// silently leaving it for a drain that already completed.
    public func setLifecycleHandler(_ handler: @escaping @Sendable (HsLifecycleEvent) -> Void) throws {
        // Reject in Closing/Closed/drain races BEFORE creating a root.
        lock.lock()
        let refused = drained || closeRequested || freed || roots.count >= HsEngineContext.maxRegistrations
        lock.unlock()
        if refused { throw HsStatus.state }

        // Pin first: a failed pin after free must not retain a root.
        let ptr = try pinnedCtx()
        // One pin lifetime covers retain + native call + root publication.
        defer { unpinCtx() }

        let box = CallbackRootBox(handler: handler)
        // passRetained: +1 owned by the registration until drain (or until a
        // post-drain publication is released under proven quiescence).
        let user = Unmanaged.passRetained(box).toOpaque()
        // Non-throwing C call: no do/catch around it.
        let st = hs_viewer_set_lifecycle_cb(
            ptr,
            { user, code, generation in
                guard let user else { return }
                let box = Unmanaged<CallbackRootBox>.fromOpaque(user).takeUnretainedValue()
                box.invoke(HsLifecycleEvent(code: code, generation: generation))
            },
            user
        )
        guard st == 0 else {
            // Failed native publication: free ONLY the unpublished root, once.
            Unmanaged<CallbackRootBox>.fromOpaque(user).release()
            if st == 3 { throw HsStatus.state }
            if st == 5 { throw HsStatus.exhausted }
            throw HsStatus(raw: st)
        }
        lock.lock()
        if drained || freed {
            // Native accepted the root, but drain/free already proved worker
            // quiescence (free requires drain). Release now under that proof
            // instead of leaving the root for a drain that already completed.
            lock.unlock()
            Unmanaged<CallbackRootBox>.fromOpaque(user).release()
            throw HsStatus.state
        }
        // Publication: track the root.
        roots.append(Unmanaged<CallbackRootBox>.fromOpaque(user))
        lock.unlock()
    }

    /// Poll one lifecycle event without a callback. Returns nil when empty.
    public func pollLifecycle() throws -> HsLifecycleEvent? {
        try withCtx { ptr in
            var code: UInt32 = 0
            var gen: UInt32 = 0
            let st = hs_viewer_poll_life(ptr, &code, &gen)
            if st == 3 { return nil }
            guard st == 0 else { throw HsStatus(raw: st) }
            return HsLifecycleEvent(code: code, generation: gen)
        }
    }

    /// Queue one lifecycle event (laboratory proof hook). Not media and not
    /// authority. Refused outside Prepared.
    public func debugQueueLife(code: UInt32, generation: UInt32) throws {
        try withCtx { ptr in
            let st = hs_debug_queue_life(ptr, code, generation)
            guard st == 0 else { throw HsStatus(raw: st) }
        }
    }

    /// Free after drain. Refuses while any call is pinned or before drain.
    public func freeAfterDrain() throws {
        lock.lock()
        if freed {
            lock.unlock()
            return
        }
        // Pin count must be zero: refuse rather than free a live native call.
        guard drained, pinned == 0, let p = ctx else {
            lock.unlock()
            throw HsStatus.state
        }
        freed = true
        ctx = nil
        let toRelease = roots
        roots = []
        lock.unlock()
        let st = hs_engine_ctx_free(p)
        // Worker is joined (drained). Release every root.
        for r in toRelease { r.release() }
        guard st == 0 else { throw HsStatus(raw: st) }
    }

    // MARK: - Pinning

    private func pinnedCtx() throws -> OpaquePointer {
        lock.lock()
        defer { lock.unlock() }
        guard !freed, let p = ctx else { throw HsStatus.state }
        pinned += 1
        return p
    }

    private func unpinCtx() {
        lock.lock()
        pinned -= 1
        lock.unlock()
    }

    private func withCtx<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        let p = try pinnedCtx()
        defer { unpinCtx() }
        return try body(p)
    }
}
