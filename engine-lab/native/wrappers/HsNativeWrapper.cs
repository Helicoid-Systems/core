// HsNativeWrapper.cs — Helicoid RD02 C# wrapper over the generated C ABI.
//
// GENERATED-CONTRACT: consumes `native/hs_native.h` exactly. Never guess a
// layout. Run `scripts/check-wrapper-contract.py` after any header change.
//
// Scope (lab only):
//   - owns one hs_engine_ctx* and prevents double free (SafeHandle)
//   - marshals the exact hs_frame_desc (distinct layout/interaction admission
//     fences and the separate viewer/cancel generation)
//   - roots EVERY lifecycle registration with an independent GCHandle until
//     proven drain, including replacement and abandoned wrappers
//   - distinguishes close-request (non-blocking) from safely drained
//   - no mock pixels, identities, grants, or media in normal construction
//
// Prepared means inert. Connect/observation/channel-binding stay unavailable
// until a real authenticated channel and sealed HS endpoint admission exist.
// This wrapper is not an authorization surface.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Helicoid.EngineLab
{
    /// <summary>Status codes from hs_native.h.</summary>
    public enum HsStatus : uint
    {
        Ok = 0,
        Invalid = 1,
        Null = 2,
        State = 3,
        Panic = 4,
        Exhausted = 5,
        Unavailable = 6,
        Internal = 7,
        Bounds = 8,
        Timeout = 9,
        Handshake = 10,
    }

    /// <summary>Exception carrying a native status code.</summary>
    public sealed class HsException : Exception
    {
        public HsStatus Status { get; }
        public HsException(HsStatus status, string op)
            : base($"{op} failed with {status} ({(uint)status})")
            => Status = status;
    }

    /// <summary>Context lifecycle states from hs_native.h.</summary>
    public enum HsSessionState : uint
    {
        Created = 0,
        Prepared = 1,
        Closing = 2,
        Closed = 3,
    }

    /// <summary>
    /// Exact hs_frame_desc layout from the generated header.
    /// Field order and widths must match native/hs_native.h.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct HsFrameDesc
    {
        public uint Width;
        public uint Height;
        public uint Stride;
        public uint Format;
        public uint Length;
        public uint Display;
        /// <summary>Context/cancellation fence. Separate from admission fences.</summary>
        public uint ViewerGeneration;
        /// <summary>Frame-admission fence: layout revision (nonzero, bounded).</summary>
        public uint LayoutGeneration;
        /// <summary>Frame-admission fence: interaction generation (nonzero, bounded).</summary>
        public uint InteractionGeneration;
        public ulong Sequence;
    }

    /// <summary>Lifecycle event delivered on the engine delivery worker.</summary>
    public sealed class HsLifecycleEvent
    {
        public uint Code { get; }
        public uint Generation { get; }
        public HsLifecycleEvent(uint code, uint generation)
        {
            Code = code;
            Generation = generation;
        }
        public bool IsFrameReady => Code == 1;
        public bool IsClosing => Code == 2;
        public bool IsDrained => Code == 3;
    }

    internal static class HsNativeMethods
    {
        private const string Lib = "librustdesk";

        [DllImport(Lib, EntryPoint = "hs_abi_version", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_abi_version();

        [DllImport(Lib, EntryPoint = "hs_engine_ctx_new", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_engine_ctx_new(out IntPtr ctx);

        [DllImport(Lib, EntryPoint = "hs_engine_ctx_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_engine_ctx_free(IntPtr ctx);

        [DllImport(Lib, EntryPoint = "hs_viewer_prepare", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_viewer_prepare(IntPtr ctx);

        [DllImport(Lib, EntryPoint = "hs_viewer_state", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_viewer_state(IntPtr ctx, out uint state);

        [DllImport(Lib, EntryPoint = "hs_viewer_request_close", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_viewer_request_close(IntPtr ctx);

        [DllImport(Lib, EntryPoint = "hs_viewer_drain", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_viewer_drain(IntPtr ctx, uint timeoutMs);

        [DllImport(Lib, EntryPoint = "hs_frame_acquire_latest", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_frame_acquire_latest(
            IntPtr ctx, uint display, out IntPtr frame, out HsFrameDesc desc);

        [DllImport(Lib, EntryPoint = "hs_frame_pixels", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_frame_pixels(
            IntPtr frame, out IntPtr pixels, out uint length);

        [DllImport(Lib, EntryPoint = "hs_frame_get_desc", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_frame_get_desc(IntPtr frame, out HsFrameDesc desc);

        [DllImport(Lib, EntryPoint = "hs_frame_release", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_frame_release(IntPtr frame);

        [DllImport(Lib, EntryPoint = "hs_viewer_set_lifecycle_cb", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_viewer_set_lifecycle_cb(
            IntPtr ctx, HsLifecycleCb cb, IntPtr user);

        [DllImport(Lib, EntryPoint = "hs_viewer_poll_life", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_viewer_poll_life(
            IntPtr ctx, out uint code, out uint generation);

        [DllImport(Lib, EntryPoint = "hs_debug_queue_life", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_debug_queue_life(IntPtr ctx, uint code, uint generation);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void HsLifecycleCb(IntPtr user, uint code, uint generation);
    }

    /// <summary>
    /// One rooted lifecycle registration. The userdata GCHandle roots a small
    /// <see cref="UserData"/> record (registration + handler), not the whole
    /// wrapper, so the wrapper itself can be collected while the thunk stays
    /// alive for an in-flight native callback. The delegate thunk is the
    /// permanently rooted static trampoline — no per-registration thunk root.
    /// </summary>
    internal sealed class Registration
    {
        public HsNativeMethods.HsLifecycleCb Thunk;
        public GCHandle UserHandle;
        public bool Published;
    }

    /// <summary>
    /// Owns one native context. Prevents double free via SafeHandle.
    /// Tear down with RequestClose() then Drain() then Dispose()/FreeAfterDrain().
    ///
    /// Concurrency model (honest):
    /// - Native calls are serialised under an internal gate and AddRef the
    ///   SafeHandle for the duration of each P/Invoke.
    /// - Every lifecycle registration is rooted by an independent GCHandle
    ///   until proven drain. Replacement and abandoned wrappers keep old
    ///   roots alive. Drain releases every root.
    /// - FreeBeforeDrain is refused; free after drain releases roots then
    ///   frees the context exactly once.
    /// - Managed exceptions are contained in the static trampoline.
    /// </summary>
    public sealed class HsEngineContext : IDisposable
    {
        private sealed class CtxHandle : SafeHandle
        {
            private int _freeResult = (int)HsStatus.Ok;
            public CtxHandle(IntPtr raw) : base(IntPtr.Zero, ownsHandle: true)
            {
                SetHandle(raw);
            }
            public override bool IsInvalid => handle == IntPtr.Zero;
            /// <summary>Result of the last native free attempt (Ok, State, ...).</summary>
            public HsStatus LastFreeResult => (HsStatus)(uint)_freeResult;
            protected override bool ReleaseHandle()
            {
                // Native free refuses (STATE) while the worker is live.
                // Do NOT pretend success: record the real result so callers
                // and finalizer diagnostics can observe it.
                uint st = HsNativeMethods.hs_engine_ctx_free(handle);
                _freeResult = (int)st;
                // Return true only when the native side actually freed.
                // Returning false marks the SafeHandle as broken, which is
                // honest: the handle may still be live in native code.
                return st == 0;
            }
        }

        private readonly CtxHandle _handle;
        private readonly object _gate = new object();
        private bool _closeRequested;
        private bool _drained;
        private bool _disposed;

        /// <summary>ABI version this wrapper was written against (HS_ABI_VERSION).</summary>
        public const uint ExpectedAbiVersion = 2;

        /// <summary>
        /// Maximum published registrations accepted by native: one initial
        /// registration plus HS_MAX_LIFE_RETIRED (8) replacements.
        /// </summary>
        public const int MaxRegistrations = 9;

        /// <summary>
        /// Every published registration, rooted by GCHandle until drain.
        /// Bounded: native HS_MAX_LIFE_RETIRED limits replacements.
        /// </summary>
        private readonly List<Registration> _registrations = new List<Registration>();

        /// <summary>Stable static trampoline. Recoveries userdata via GCHandle.
        /// Permanently rooted for the process lifetime.</summary>
        private static readonly HsNativeMethods.HsLifecycleCb s_trampoline = StaticTrampoline;

        public HsEngineContext()
        {
            // Validate the linked ABI BEFORE allocating a context. Loading an
            // incompatible library must fail closed rather than interpret a
            // mismatched frame descriptor.
            var abi = HsNativeMethods.hs_abi_version();
            if (abi != ExpectedAbiVersion)
                throw new HsException(HsStatus.Internal, "hs_abi_version");
            var st = HsNativeMethods.hs_engine_ctx_new(out var raw);
            if (st != 0 || raw == IntPtr.Zero)
                throw new HsException((HsStatus)st, "hs_engine_ctx_new");
            _handle = new CtxHandle(raw);
        }

        /// <summary>Number of rooted registrations (diagnostics).</summary>
        public int RootedRegistrationCount
        {
            get { lock (_gate) { return _registrations.Count; } }
        }

        /// <summary>Construct the real inert Session. Prepared is inert.</summary>
        public void Prepare()
        {
            using (new HandlePin(_handle, _gate))
            {
                var st = HsNativeMethods.hs_viewer_prepare(_handle.DangerousGetHandle());
                if (st != 0) throw new HsException((HsStatus)st, "hs_viewer_prepare");
            }
        }

        public HsSessionState State()
        {
            using (new HandlePin(_handle, _gate))
            {
                var st = HsNativeMethods.hs_viewer_state(
                    _handle.DangerousGetHandle(), out var raw);
                if (st != 0) throw new HsException((HsStatus)st, "hs_viewer_state");
                return (HsSessionState)raw;
            }
        }

        /// <summary>Non-blocking close request. Distinguishes from IsSafelyDrained.
        /// Safe to call from inside a lifecycle callback.</summary>
        public void RequestClose()
        {
            using (new HandlePin(_handle, _gate))
            {
                var st = HsNativeMethods.hs_viewer_request_close(_handle.DangerousGetHandle());
                if (st != 0 && st != 3)
                    throw new HsException((HsStatus)st, "hs_viewer_request_close");
            }
            lock (_gate) { _closeRequested = true; }
        }

        /// <summary>
        /// Bounded async drain. Throws Timeout if the deadline expires.
        /// On success marks safely drained and releases EVERY registration root.
        ///
        /// The wrapper gate is NOT held while the native drain waits, so a
        /// lifecycle callback may re-enter RequestClose without deadlocking.
        /// The SafeHandle is AddRef'd for the call so FreeAfterDrain cannot
        /// free the pointer mid-drain.
        /// </summary>
        public void Drain(uint timeoutMs)
        {
            uint st;
            bool added = false;
            _handle.DangerousAddRef(ref added);
            try
            {
                st = HsNativeMethods.hs_viewer_drain(_handle.DangerousGetHandle(), timeoutMs);
            }
            finally
            {
                _handle.DangerousRelease();
            }
            if (st != 0) throw new HsException((HsStatus)st, "hs_viewer_drain");
            lock (_gate)
            {
                _drained = true;
                ReleaseAllRoots();
            }
        }

        /// <summary>True only after Drain completed.</summary>
        public bool IsSafelyDrained
        {
            get { lock (_gate) { return _drained; } }
        }

        public bool IsCloseRequested
        {
            get { lock (_gate) { return _closeRequested; } }
        }

        /// <summary>
        /// Acquire the latest owned frame. Returns null when no frame exists.
        /// The handle must be disposed exactly once.
        /// </summary>
        public HsFrameHandle AcquireLatestFrame(uint display)
        {
            using (new HandlePin(_handle, _gate))
            {
                var st = HsNativeMethods.hs_frame_acquire_latest(
                    _handle.DangerousGetHandle(), display, out var frame, out var desc);
                if (st == 3) return null;
                if (st != 0) throw new HsException((HsStatus)st, "hs_frame_acquire_latest");
                return new HsFrameHandle(frame, desc);
            }
        }

        /// <summary>
        /// Register a lifecycle handler. Invoked on the engine delivery
        /// worker — never the UI thread.
        ///
        /// Rooting: the thunk is the permanently rooted static trampoline;
        /// the userdata is a GCHandle to a small <see cref="Registration"/>
        /// record (not the wrapper). The handle stays alive until drain,
        /// independent of wrapper reachability. Replacement roots a NEW
        /// registration and keeps the old one until drain. Failed registration
        /// frees only the unpublished root. Registration is refused after
        /// drain/close and beyond the native bound.
        ///
        /// Atomicity: the native call and registration publication run under
        /// the same wrapper gate (HandlePin holds Monitor + AddRef). Drain
        /// cannot mark _drained or free between native accept and bookkeeping.
        /// The gate is NOT held across the native drain wait.
        /// </summary>
        public void SetLifecycleHandler(Action<HsLifecycleEvent> handler)
        {
            if (handler == null) throw new ArgumentNullException(nameof(handler));

            var reg = new Registration();
            // Root the handler closure via the Registration record.
            // The GCHandle targets only `reg`, not `this`.
            reg.Thunk = s_trampoline;
            reg.UserHandle = GCHandle.Alloc(new UserData(reg, handler), GCHandleType.Normal);
            try
            {
                // Hold the wrapper gate across the native call AND publication.
                // Monitor is re-entrant so HandlePin can enter _gate again.
                lock (_gate)
                {
                    if (_closeRequested || _drained || _disposed)
                    {
                        throw new HsException(HsStatus.State, "hs_viewer_set_lifecycle_cb");
                    }
                    if (_registrations.Count >= MaxRegistrations)
                    {
                        throw new HsException(HsStatus.Exhausted, "hs_viewer_set_lifecycle_cb");
                    }
                    using (new HandlePin(_handle, _gate))
                    {
                        var st = HsNativeMethods.hs_viewer_set_lifecycle_cb(
                            _handle.DangerousGetHandle(),
                            reg.Thunk,
                            GCHandle.ToIntPtr(reg.UserHandle));
                        if (st != 0)
                        {
                            // Failed native publication: free ONLY the
                            // unpublished root, once. No publication.
                            throw new HsException((HsStatus)st, "hs_viewer_set_lifecycle_cb");
                        }
                        // Publication under the same gate as the native call.
                        // Drain's _drained write also needs _gate, so it cannot
                        // interleave bookkeeping.
                        reg.Published = true;
                        _registrations.Add(reg);
                    }
                }
            }
            catch
            {
                // Any throw before publication must free the unpublished root
                // exactly once. A native-accepted (published) root is never
                // freed here — drain/release owns it under proven quiescence.
                if (!reg.Published && reg.UserHandle.IsAllocated)
                {
                    reg.UserHandle.Free();
                }
                throw;
            }
        }

        /// <summary>Poll one lifecycle event. Returns null when empty.</summary>
        public HsLifecycleEvent PollLifecycle()
        {
            using (new HandlePin(_handle, _gate))
            {
                var st = HsNativeMethods.hs_viewer_poll_life(
                    _handle.DangerousGetHandle(), out var code, out var generation);
                if (st == 3) return null;
                if (st != 0) throw new HsException((HsStatus)st, "hs_viewer_poll_life");
                return new HsLifecycleEvent(code, generation);
            }
        }

        /// <summary>
        /// Queue one lifecycle event (laboratory proof hook). Not media and
        /// not authority. Refused outside Prepared.
        /// </summary>
        public void DebugQueueLife(uint code, uint generation)
        {
            using (new HandlePin(_handle, _gate))
            {
                var st = HsNativeMethods.hs_debug_queue_life(
                    _handle.DangerousGetHandle(), code, generation);
                if (st != 0) throw new HsException((HsStatus)st, "hs_debug_queue_life");
            }
        }

        /// <summary>
        /// Free after drain. Refuses if drain has not completed (State).
        /// Releases every registration root, then frees the context once.
        /// </summary>
        public void FreeAfterDrain()
        {
            lock (_gate)
            {
                if (_disposed) return;
                if (!_drained) throw new HsException(HsStatus.State, "FreeAfterDrain");
                _disposed = true;
                ReleaseAllRoots();
            }
            _handle.Dispose();
            var freeResult = _handle.LastFreeResult;
            if (freeResult != HsStatus.Ok)
                throw new HsException(freeResult, "hs_engine_ctx_free");
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed) return;
                if (_drained)
                {
                    _disposed = true;
                    ReleaseAllRoots();
                }
                else
                {
                    throw new HsException(HsStatus.State,
                        "Dispose before Drain; call RequestClose + Drain first");
                }
            }
            _handle.Dispose();
        }

        /// <summary>Release every registration GCHandle. Caller holds _gate.
        /// Releases only roots that were published (or unpublished leftovers
        /// already freed at failure). The static trampoline stays rooted.</summary>
        private void ReleaseAllRoots()
        {
            foreach (var reg in _registrations)
            {
                if (reg.UserHandle.IsAllocated) reg.UserHandle.Free();
            }
            _registrations.Clear();
        }

        /// <summary>Userdata passed to the native trampoline. Roots only this
        /// small record and the handler — not the whole wrapper.</summary>
        private sealed class UserData
        {
            public readonly Registration Reg;
            public readonly Action<HsLifecycleEvent> Handler;
            public UserData(Registration reg, Action<HsLifecycleEvent> handler)
            {
                Reg = reg;
                Handler = handler;
            }
        }

        /// <summary>
        /// Stable static trampoline. Recovers <see cref="UserData"/> from the
        /// GCHandle pointer. Contains managed exceptions so they never cross
        /// the native ABI. Does not touch the wrapper, so an abandoned wrapper
        /// can be collected while this still runs.
        /// </summary>
        private static void StaticTrampoline(IntPtr user, uint code, uint generation)
        {
            if (user == IntPtr.Zero) return;
            UserData data = null;
            try
            {
                var h = GCHandle.FromIntPtr(user);
                data = h.Target as UserData;
            }
            catch
            {
                return;
            }
            if (data?.Handler == null) return;
            try
            {
                data.Handler(new HsLifecycleEvent(code, generation));
            }
            catch
            {
                // Contain managed exceptions: never unwind across native.
            }
        }

        /// <summary>
        /// AddRef/Release the SafeHandle around a native call so a concurrent
        /// FreeAfterDrain cannot free the pointer mid-call.
        /// Constructor releases the Monitor if DangerousAddRef throws.
        /// </summary>
        private sealed class HandlePin : IDisposable
        {
            private readonly CtxHandle _h;
            private readonly object _gate;
            private readonly bool _entered;
            private readonly bool _added;
            public HandlePin(CtxHandle h, object gate)
            {
                _h = h;
                _gate = gate;
                System.Threading.Monitor.Enter(gate, ref _entered);
                bool added = false;
                try
                {
                    h.DangerousAddRef(ref added);
                    _added = added;
                }
                catch
                {
                    if (_entered) System.Threading.Monitor.Exit(gate);
                    throw;
                }
            }
            public void Dispose()
            {
                if (_added) _h.DangerousRelease();
                if (_entered) System.Threading.Monitor.Exit(_gate);
            }
        }
    }

    /// <summary>Owned frame handle. Dispose is exactly-once (SafeHandle).</summary>
    public sealed class HsFrameHandle : IDisposable
    {
        private sealed class FrameHandle : SafeHandle
        {
            public FrameHandle(IntPtr raw) : base(IntPtr.Zero, ownsHandle: true)
            {
                SetHandle(raw);
            }
            public override bool IsInvalid => handle == IntPtr.Zero;
            protected override bool ReleaseHandle()
            {
                HsNativeMethods.hs_frame_release(handle);
                return true;
            }
        }

        private readonly FrameHandle _handle;
        private readonly HsFrameDesc _desc;

        internal HsFrameHandle(IntPtr raw, HsFrameDesc desc)
        {
            _handle = new FrameHandle(raw);
            _desc = desc;
        }

        /// <summary>Exact generated descriptor. Never guess a layout.</summary>
        public HsFrameDesc Desc => _desc;

        /// <summary>
        /// Borrow the immutable pixel buffer. Valid until Dispose.
        /// Returns false after release.
        /// </summary>
        public bool TryWithPixels(out IntPtr pixels, out uint length)
        {
            pixels = IntPtr.Zero;
            length = 0;
            if (_handle.IsInvalid || _handle.IsClosed) return false;
            var st = HsNativeMethods.hs_frame_pixels(
                _handle.DangerousGetHandle(), out pixels, out length);
            return st == 0 && pixels != IntPtr.Zero;
        }

        /// <summary>Exact allocator release. Idempotent via SafeHandle.</summary>
        public void Dispose() => _handle.Dispose();

        public bool IsLive => !_handle.IsInvalid && !_handle.IsClosed;
    }
}
