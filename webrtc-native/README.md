# webrtc-native (E01 selected route: Google WebRTC)

Draft candidate, 14 October 2026: only this README, the upstream pin manifest
and the C++ bridge source are present. Generated headers, wrappers, build
scripts and the executable harness below are unfinished target deliverables.
The coordinator has identified unresolved handle ownership, callback drain,
queue-bound and certificate-invalidation defects. MiMo stopped with provider
HTTP 402. No native build, connection or adoption is verified.

Helicoid Systems native Google **WebRTC** connection laboratory for **E01**.
This package replaces RustDesk as the **selected** engine route. The historical
RustDesk laboratory under `../engine-lab/**` is retained unchanged; nothing here
rewrites that evidence.

Owned path: `modules/core/webrtc-native/**`. Large upstream checkouts and build
trees live only in the dedicated scratch directory given to the build scripts
(default `/tmp/hs-finish-20261013/webrtc-upstream`), never inside this crate.

## Target deliverables (incomplete)

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
- Windows native acceptance remains **Not Verified** until real Windows CI
  completes (`.github/workflows/webrtc-native-windows.yml` is the pending gate).
  Latest native CI failed at GN gen because the pinned Chromium checkout requires
  Windows SDK **10.0.28000.0** (hardcoded in `vs_toolchain.py` /
  `setup_toolchain.py`); hosted runners ship 26100. An official Microsoft
  servicing install of **10.0.28000.2957** is now a bounded CI prerequisite
  (`inventory/win-sdk-pins.json`, `scripts/install-win-sdk.ps1`) before fetch.
  Do not downgrade the pin or claim a Windows pass from folder existence alone.
  Preflight requires observed installed servicing metadata (registry/tool
  versions), not unversioned headers or empty placeholders. Installer download
  is byte-bounded and process-wait is tree-scoped. **No Windows runtime claim**
  until real CI installs the pinned SDK and completes GN/ninja/harness.

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

# 3. Cross-build macOS x86_64 (binary produced; run under Rosetta if available)
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
