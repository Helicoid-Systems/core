# webrtc-native (E01 selected route: Google WebRTC)

Bounded prerequisite status, 17 October 2026: generated header and wrappers
are present and checked. Real arm64 bridge + harness and own-bridge ASan have
passed **142 checks**; Swift and C# wrapper runtimes passed **13** and **16**
checks against the real shared library. Intel cross-compile produces binaries;
Intel runtime is **Not Verified**. Windows CI 38971753484 actually installed
the pinned Windows SDK 10.0.28000.2957 and compiled bridge/DLL/harness, then
failed **24/100** native harness checks at `peer A/B channel/connected`. Missing
Winsock initialization was identified in source; the WSA ownership repair is pending a native Windows CI rerun. No
accepted core pin advance. Media, capture, input, admission and public relay
adoption remain unavailable. This is a connection-lab prerequisite only — not
a full plan, normal factory, or production claim.

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
  negotiation, bounded data-channel product messages, channel-evidence
  (verified DTLS peer certificate) and drain/close.
- A C header (`native/hs_webrtc.h`) **generated** from implemented exports by
  `scripts/gen_header.py`. Do not hand-edit the header.
- A native executable harness (`native/harness.cpp`) that establishes **two real
  PeerConnections**, generates **real DTLS certificates**, performs offer/answer
  and ICE exchange, opens a data channel, and proves channel evidence and
  tampered-expected-certificate denial through the actual engine.
- Swift / C# wrappers (`native/wrappers/**`) covering **only** the exports this
  package implements.

## What this package is not

- Not a media bridge, not capture, not input injection, not admission, not an
  authentication/grant protocol.
- Production **capture / admission / media** stay explicitly unavailable
  (`hs_engine_capabilities` does not set those bits; related calls return
  `HS_STATUS_UNAVAILABLE`). No frame or input success is claimed without later
  real endpoint admission.
- A caller-supplied SDP fingerprint string is **not** verified identity. Peer
  identity is taken only from the **negotiated** certificate chain on a
  **connected** DTLS transport (`DtlsTransportState::kConnected` /
  `remote_ssl_certificates()`).
- The opaque **verified-channel handle** is engine-issued, bound to one peer
  generation, and invalidated on close, DTLS failure, or replacement. It cannot
  be fabricated from caller identity data.
- Windows native acceptance remains **Not Verified**. CI 38971753484 installed
  the pinned Windows SDK **10.0.28000.2957** (`inventory/win-sdk-pins.json`,
  `scripts/install-win-sdk.ps1`) and compiled bridge/DLL/harness, then the
  harness failed **24/100** checks at `peer A/B channel/connected`. Source review
  identified missing Winsock startup (`webrtc::WinsockInitializer`). The WSA
  ownership repair is pending a native Windows CI rerun. Do not downgrade the
  SDK pin or claim a Windows pass from compile-only evidence. Preflight
  requires observed installed servicing metadata (registry/tool versions), not
  unversioned headers or empty placeholders. **No Windows runtime claim**
  until a native rerun completes GN/ninja/harness green. No accepted core pin
  advance.

## ABI-3 subset

| Area | Exports |
|---|---|
| Version / init | `hs_abi_version`, `hs_engine_version`, `hs_engine_init`, `hs_engine_shutdown`, `hs_engine_capabilities` |
| Peer lifecycle | `hs_peer_create`, `hs_peer_close`, `hs_peer_free`, `hs_peer_generation`, `hs_peer_state` |
| Negotiation | `hs_peer_create_offer`, `hs_peer_create_answer`, `hs_peer_set_local`, `hs_peer_set_remote`, `hs_peer_add_ice`, `hs_peer_poll_ice` |
| Data channel | `hs_channel_create`, `hs_channel_send`, `hs_channel_poll`, `hs_channel_close` |
| Channel evidence | `hs_peer_expected_cert_set`, `hs_verified_channel_acquire`, `hs_verified_channel_export`, `hs_verified_channel_generation`, `hs_verified_channel_release` |
| Drain | `hs_peer_drain`, `hs_engine_drain` |

Absent production capture / admission / media surfaces stay out of this ABI and
are reported `UNAVAILABLE` via capability bits and guarded calls.

## Build and harness

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

Windows x64 CI: `.github/workflows/webrtc-native-windows.yml` (timeouts,
retained binary + harness reports). Until that workflow runs on real Windows
runners, Windows native acceptance is **Not Verified**.

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
