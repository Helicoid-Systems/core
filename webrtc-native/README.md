# webrtc-native (E01 selected route: Google WebRTC)

Bounded prerequisite status, 17 October 2026: core baseline `eab1939` passes
142 native Windows engine checks and 16 C# runtime checks in CI39037906193.
The downloaded unsigned DLL/harness and generated exports were independently
inspected. This is native Windows Server2025 evidence; installed Windows11
acceptance remains Not Verified.

The separate TURN/TLS candidate passes real macOS arm64 loopback connections
with REST authentication, exact PEM and SHA-256 pins, negotiated certificates,
opaque channel handles and bidirectional product messages. Generated headers
and wrappers are checked. Current candidate checks include142 native and142
own-bridge ASan checks,22 Swift and16 C# runtime checks. Intel cross-build is
available; Intel runtime and Windows TURN runtime remain Not Verified. Public
TCP443, OS UDP blocking, endpoint admission, capture, media and input remain
unavailable or Not Verified. See the owning BUILD-REPORT for bounded evidence;
this package does not pass the full engine adoption or product checkpoint.

Helicoid Systems native Google **WebRTC** connection laboratory for **E01**.
This package replaces RustDesk as the **selected** engine route. The historical
RustDesk laboratory under `../engine-lab/**` is retained unchanged; nothing here
rewrites that evidence.

Owned path: `modules/core/webrtc-native/**`. Large upstream checkouts and build
trees live only in the dedicated scratch directory given to the build scripts
(default `/tmp/hs-finish-20261013/webrtc-upstream`), never inside this crate.

## Package contents

- A **pinned** Google WebRTC source / DEPS / toolchain manifest
  (`inventory/upstream-pins.json`).
- Reproducible **bounded** build scripts (`scripts/fetch-upstream.sh`,
  `scripts/build-macos.sh`, `scripts/build-windows.ps1`) that use
  `depot_tools` + GN + Ninja against an exact revision.
- A real C++ bridge (`native/hs_webrtc_bridge.cpp`) implementing the **ABI-3
  subset**: engine initialization, owned peer lifecycle, offer/answer + ICE
  negotiation, bounded data-channel product messages gated by a live
  verified-channel binding, channel-evidence
  (verified DTLS peer certificate), exact shared channel binding, bounded
  admission-fenced video primitives, and drain/close.
- A dependency-free canonical binding encoder (`native/channel_binding.h`)
  with a standalone exact-byte regression check (`native/channel_binding_test.cpp`).
- A C header (`native/hs_webrtc.h`) **generated** from implemented exports by
  `scripts/gen_header.py`. Do not hand-edit the header.
- A native executable harness (`native/harness.cpp`) that establishes **two real
  PeerConnections**, generates **real DTLS certificates**, performs offer/answer
  and ICE exchange, opens a data channel, and proves channel evidence and
  tampered-expected-certificate denial through the actual engine.
- Swift / C# wrappers (`native/wrappers/**`) covering **only** the exports this
  package implements.

## What this package is not

- The bridge now contains bounded video primitives: send-only peers accept
  tightly sized BGRA frames, convert them to I420, and send them through a
  WebRTC video track; receive-only peers convert their latest admitted frame
  into a bounded BGRA mailbox. Admission is fenced to a live verified channel
  binding and a short monotonic lease.
- The Qt Manager source now connects grant issuance, attested signaling,
  verified-channel proof, lease start, and frame display. The Windows Computer
  source verifies and redeems endpoint grants, checks physical-console
  eligibility, captures bounded frames, and feeds its native sender. These
  application paths remain source-only in this checkout.
- `hs_engine_capabilities` continues to leave **capture, admission, and media
  disabled**. The Windows native DLL is absent from the retained inventory,
  and the current environment cannot compile the Qt 6.10 Manager or Windows
  C# endpoint. No end-to-end pixel delivery or observation acceptance is
  claimed.
- This package still does not implement input injection or an authentication /
  grant protocol. A host must verify server-issued authority first; the bridge
  only binds that already verified authority to the current channel and lease.
- A caller-supplied SDP fingerprint string is **not** verified identity. Peer
  identity is taken only from the **negotiated** certificate chain on a
  **connected** DTLS transport (`DtlsTransportState::kConnected` /
  `remote_ssl_certificates()`).
- The opaque **verified-channel handle** is engine-issued, bound to one peer
  generation, and invalidated on close, loss of connected DTLS state, or
  certificate replacement. It cannot be fabricated from caller identity data.
- Data-channel send and poll return `HS_STATUS_HANDSHAKE` without a live verified
  binding. Incoming data is dropped before pinning; buffered data is discarded
  whenever the binding is invalidated or replaced.
- Windows baseline native acceptance is Verified in
  [CI39037906193](https://github.com/Helicoid-Systems/core/actions/runs/39037906193):
  142 engine checks,16 C# runtime checks, actual unsigned x64 DLL/harness.
  TURN is absent from that baseline; its Windows runtime remains Not Verified.
  The pinned SDK remains10.0.28000.2957. Preserve its servicing-version check.

## ABI-3 subset

| Area | Exports |
|---|---|
| Version / init | `hs_abi_version`, `hs_engine_version`, `hs_engine_init`, `hs_engine_shutdown`, `hs_engine_capabilities` |
| Peer lifecycle | `hs_peer_create`, `hs_peer_close`, `hs_peer_free`, `hs_peer_generation`, `hs_peer_state` |
| Negotiation | `hs_peer_create_offer`, `hs_peer_create_answer`, `hs_peer_set_local`, `hs_peer_set_remote`, `hs_peer_add_ice`, `hs_peer_poll_ice` |
| Data channel | `hs_channel_create`, `hs_channel_send`, `hs_channel_poll`, `hs_channel_close` |
| Channel evidence | `hs_peer_expected_cert_set`, `hs_verified_channel_acquire`, `hs_verified_channel_export`, `hs_verified_channel_binding_export`, `hs_verified_channel_generation`, `hs_verified_channel_release` |
| Drain | `hs_peer_drain`, `hs_engine_drain` |
| Video and observation primitives | `hs_peer_video_prepare`, `hs_admission_begin`, `hs_admission_end`, `hs_capture_begin`, `hs_capture_end`, `hs_peer_video_frame_push`, `hs_media_frame_acquire` |

### Current WebRTC channel binding

`hs_verified_channel_binding_export` returns a bounded, identical binding on
both peers for the current `hs-product` data channel. It contains a domain tag,
the product label, the SCTP stream ID (0–65534; RFC 8832 reserves 65535), and
the lexicographically sorted SHA-256 digests of both local/negotiated DTLS leaf
certificates. Fingerprints come from WebRTC certificate objects; caller SDP
text is not used. The handle is invalidated on certificate replacement,
transport loss, channel close, or peer close, so a stale channel cannot export
its binding. Certificate and binding exports serialize with those peer
transitions and require the handle to remain the peer's current open product
channel for the full export. Both
exports clear `out_len` before validation, including when the handle is stale.

This binds a peer proof to one actual WebRTC data channel. It does not identify
the Manager or endpoint's product key or issue server authority. The bounded
video and lease primitives require the host to verify that authority first;
their capability bits remain off until the application integrations and
end-to-end acceptance are complete.

## Build and harness

The channel-binding byte layout can be checked without downloading or building
Google WebRTC:

```bash
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -I native \
  native/channel_binding_test.cpp -o /tmp/hs-webrtc-channel-binding-test
/tmp/hs-webrtc-channel-binding-test
```

Sensitive frame-buffer wiping can be checked independently of Google WebRTC:

```bash
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -I native \
  native/secure_memory_test.cpp -o /tmp/hs-webrtc-secure-memory-test
/tmp/hs-webrtc-secure-memory-test
```

```bash
# 1. Fetch pinned upstream into scratch (requires depot_tools on PATH)
./scripts/fetch-upstream.sh /tmp/hs-finish-20261013/webrtc-upstream

# 2. macOS arm64 bridge + harness (runs the real harness)
./scripts/build-macos.sh /tmp/hs-finish-20261013/webrtc-upstream out-arm64

# 3. Own-bridge ASan (name containing "asan" enables hs_asan; the script
#    resolves the pinned checkout clang's ASan dylib and fails closed if
#    it is absent. Loader path is set for the harness command only.)
./scripts/build-macos.sh /tmp/hs-finish-20261013/webrtc-upstream out-arm64-asan arm64

# 4. Cross-build macOS x86_64 (binary produced; run under Rosetta if available)
./scripts/build-macos.sh /tmp/hs-finish-20261013/webrtc-upstream out-x64 x86_64
```

Windows x64 CI: `.github/workflows/webrtc-native-windows.yml` retains binaries,
hashes and harness reports. Baseline native checks passed in run39037906193;
the newer TURN candidate requires fresh CI and has no Windows TURN runtime
acceptance yet. `build-windows.ps1` reports missing synced checkout inputs,
pinned tools, and SDK dependencies before regenerating the ABI header or
staging GN. Both platform build scripts run the shared GN helper in check-only
mode first, which checks exact source/depot_tools/DEPS pins and staging context
without writing. The Windows SDK record must match the checked-in servicing
pin and the required SDK files must exist and be non-empty.

## Header / wrapper drift

```bash
python3 scripts/gen_header.py native/hs_webrtc_bridge.cpp native/hs_webrtc.h
python3 scripts/check-header.py
python3 scripts/check-wrapper-contract.py
```

Generated-header and wrapper-drift checks are offline; platform harness runs
prove linkage.

## Relationship to core domain

`../src/**` and `../authority-lab/**` remain authoritative for domain and
authority semantics. This package is engine-connection evidence only. It does
not change domain rules, does not open public/media/control feature flags, and
does not reuse ABI-2 inert tests as WebRTC proof.
