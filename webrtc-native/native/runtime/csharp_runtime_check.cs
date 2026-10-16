// C# runtime check against hs_webrtc_shared (durable repo source).
// Exercises the HsWebRtcWrapper.cs P/Invoke surface with exact calling
// convention and honest dynamic assertion counts.
using System;
using System.Runtime.InteropServices;
using Helicoid.WebRtc;

static class Program
{
    static int checks;
    static int failures;
    static void Check(bool cond, string name)
    {
        checks++;
        if (cond) Console.WriteLine("ok   " + name);
        else { failures++; Console.WriteLine("FAIL " + name); }
    }

    static int Main()
    {
        uint abi = HsWebRtcNative.hs_abi_version();
        Check(abi == 3, "cs hs_abi_version == 3");

        IntPtr verPtr = HsWebRtcNative.hs_engine_version();
        string ver = Marshal.PtrToStringAnsi(verPtr) ?? "";
        Check(ver.StartsWith("hs-webrtc-native/"), "cs engine_version prefix");

        uint mask;
        uint cst = HsWebRtcNative.hs_engine_capabilities(out mask);
        Check(cst == 0, "cs capabilities ok");
        Check((mask & 0x10u) == 0, "cs cap capture unset");
        Check((mask & 0x20u) == 0, "cs cap admission unset");
        Check((mask & 0x40u) == 0, "cs cap media unset");

        IntPtr eng;
        uint ist = HsWebRtcNative.hs_engine_init(out eng);
        Check(ist == 0 && eng != IntPtr.Zero, "cs engine init");

        IntPtr peer;
        uint pst = HsWebRtcNative.hs_peer_create(eng, out peer);
        Check(pst == 0 && peer != IntPtr.Zero, "cs peer create");

        uint gen;
        uint gst = HsWebRtcNative.hs_peer_generation(peer, out gen);
        Check(gst == 0 && gen != 0, "cs peer generation");

        // Forged handle must fail closed (registry lookup, no caller deref).
        IntPtr forged = new IntPtr(0x1234);
        uint fv;
        uint fst = HsWebRtcNative.hs_verified_channel_valid(forged, out fv);
        Check(fst != 0 && fv == 0, "cs forged handle rejected");

        // Local cert export is real engine output.
        byte[] cert = new byte[8192];
        uint clen;
        uint cst2 = HsWebRtcNative.hs_peer_local_cert_export(peer, cert, (uint)cert.Length, out clen);
        Check(cst2 == 0 && clen > 0, "cs local cert exported");

        // Close / drain / free ownership path.
        uint closeSt = HsWebRtcNative.hs_peer_close(peer);
        Check(closeSt == 0, "cs peer close");
        uint dr = HsWebRtcNative.hs_peer_drain(peer, 1000);
        Check(dr == 0 || dr == 9 || dr == 3 || dr == 2, "cs peer drain honest");
        uint fr = HsWebRtcNative.hs_peer_free(peer);
        Check(fr == 0 || fr == 9 || fr == 3 || fr == 2, "cs peer free safe");

        uint sd = HsWebRtcNative.hs_engine_shutdown(eng);
        Check(sd == 0 || sd == 9, "cs engine shutdown");

        uint st2;
        Check(HsWebRtcNative.hs_peer_state(peer, out st2) != 0, "cs peer gone after shutdown");

        Console.WriteLine();
        Console.WriteLine("{0} checks, {1} failures", checks, failures);
        return failures == 0 ? 0 : 1;
    }
}
