// HsWebRtcWrapper.cs -- C# bindings for the E01 ABI-3 subset.
// Covers only the exports implemented by hs_webrtc_bridge.cpp.
// Opaque handles are registry tokens; never dereference them.

using System;
using System.Runtime.InteropServices;

namespace Helicoid.WebRtc
{
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

    public static class HsWebRtcNative
    {
        // Matches the built artifact: libhs_webrtc_shared.dylib / hs_webrtc_shared.dll.
        private const string Lib = "hs_webrtc_shared";

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_abi_version();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr hs_engine_version();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_engine_capabilities(out uint mask);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_engine_init(out IntPtr engine);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_engine_shutdown(IntPtr engine);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_engine_drain(IntPtr engine, uint timeoutMs);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_create(IntPtr engine, out IntPtr peer);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_close(IntPtr peer);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_free(IntPtr peer);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_generation(IntPtr peer, out uint generation);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_state(IntPtr peer, out uint state);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_local_cert_export(IntPtr peer, byte[] outBuf, uint cap, out uint outLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_channel_create(IntPtr peer, byte[] label, UIntPtr labelLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_create_offer(IntPtr peer, byte[] outSdp, UIntPtr cap, out UIntPtr outLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_create_answer(IntPtr peer, byte[] outSdp, UIntPtr cap, out UIntPtr outLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_set_local(IntPtr peer, byte[] sdp, UIntPtr sdpLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_set_remote(IntPtr peer, byte[] type, UIntPtr typeLen, byte[] sdp, UIntPtr sdpLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_add_ice(IntPtr peer, byte[] sdp, UIntPtr sdpLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_poll_ice(IntPtr peer, byte[] outSdp, UIntPtr cap, out UIntPtr outLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_channel_send(IntPtr peer, byte[] data, uint len);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_channel_poll(IntPtr peer, byte[] outBuf, uint cap, out uint outLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_channel_close(IntPtr peer);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_expected_cert_set(IntPtr peer, byte[] pem, UIntPtr pemLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_verified_channel_acquire(IntPtr peer, out IntPtr handle);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_verified_channel_export(IntPtr handle, byte[] outBuf, uint cap, out uint outLen);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_verified_channel_generation(IntPtr handle, out uint generation);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_verified_channel_valid(IntPtr handle, out uint valid);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_verified_channel_release(IntPtr handle);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint hs_peer_drain(IntPtr peer, uint timeoutMs);
    }
}
