## Coordinator native lifetime verification, 17 October 2026

Frozen bridge source `9abfe72b7a4115a77b9cc3758f132ee0659d7e3799d6b3863f19651576e5cf35`
repairs peer/observer retention after a failed drain barrier. The static harness
has a compile-only failure seam, absent from the shared library exports. The two
vacuous harness assertions are replaced with strict release/status checks.
Concurrent surviving-engine and reinitialization cases use real negotiated
connections and product messages. Header and wrappers document retiring drain
semantics without claiming two-phase free ownership.

Coordinator checks pass 142 arm64 native checks, 142 with own-bridge/harness
AddressSanitizer instrumentation, 13 Swift and 16 C# real wrapper checks, header
and wrapper drift, actionlint and PowerShell parser. Actual ASan build script
passes with the pinned compiler runtime resolved locally. A restricted-network
run fails its peer connections; the approved local-network run passes. Upstream
WebRTC archives are not sanitizer-instrumented. The deterministic failed-barrier
case does not establish arbitrary OS callback quiescence or frame disposal.
Provenance now records the actual final GN arguments, including hs_asan=true.
Intel is cross-built only; Windows runtime remains Not Verified until native CI.
Normal admission, media, capture, input and public relay adoption stay closed.
Earlier intermediate counts and failures follow.

## ASan harness runner path correction, 17 October 2026

`webrtc-native/scripts/build-macos.sh` now resolves the invoked checkout
clang's own `libclang_rt.asan_osx_dynamic.dylib` (clang major derived from the
pinned `clang++`), **fails closed** when that runtime is absent, and sets
`DYLD_LIBRARY_PATH` only on the ASan harness command so `@rpath` load is
reproducible without a global DYLD or system change. Normal non-ASan builds
are unchanged. Direct ASan harness execution previously aborted at dyld
(exit 134) because the embedded relative rpath is CWD-relative; a manual
`DYLD_LIBRARY_PATH` pass had reached 142/142. Windows CI 38971753484
(100-check suite, 24 failures at channel/connected) and the pending WSA
ownership rerun are unchanged. No accepted core pin advance. Media, capture,
input, admission and public relay adoption remain unavailable. Frozen bridge
SHA256 unchanged (`9abfe72b…`). `webrtc-native/inventory/win-sdk-prereq.txt`
remains excluded (untracked invalid inventory).

## Native Windows runtime connection + artifact retain, 17 October 2026

CI 38971753484 compiled bridge/DLL/harness after SDK+fetch gates, then harness
failed 24/100 at `peer A/B channel/connected` (offer/answer succeeded). Pinned
`examples/peerconnection` and `test_main_lib.cc` require
`webrtc::WinsockInitializer` before `CreateWithSocketServer`; the bridge never
started Winsock; this is the source-level diagnosis pending a native rerun.
Engine now owns a
process-refcounted Winsock/SSL lifetime (shutdown after network thread stops;
init failure paths release SSL refs). arm64 harness regression is **121 checks,
0 failures**, including new concurrent engine lifecycle cycles.

Upload of 8 files/10KB omitted produced binaries because inventory copies ran
only after a green harness. `build-windows.ps1` now retains harness/DLL at
build success and fails if absent; workflow `if: always()` requires those
artifacts. Windows runtime remains **Not Verified** pending native rerun.
Media/admission/capture gates stay closed.

Coordinator acceptance of the bounded CI prerequisite: actual-source download
function fetched1,450,344 bytes with the pinned SHA256; actual PowerShell parse,
strict header/wrapper drift, actionlint and diff checks pass. Empty-file and
nonempty/unknown-servicing preflight probes both fail with exit1. All112
exported assistant records verify `xiaomi-token-plan-ams/mimo-v2.6-pro`, high;
final session is stopped. Receipt: coordinator-core-sdk-final-receipt-20261016.json
in the dedicated finishing scratch directory. This is permission to exercise
the candidate in native CI; installation, Windows Authenticode, GN and harness
remain Not Verified. The accepted integration pin remains unchanged.

## Native Windows SDK 28000 candidate finalize, 16 October 2026

Lifecycle review fixed two bounded defects in `install-win-sdk.ps1`: download
now enforces the pinned byte ceiling **while streaming** (cancellable
headers/body, immutable HTTPS only), and the quiet GUI installer no longer
redirects stdout/stderr before wait (pipe-deadlock risk). Owned cleanup uses
the exact `Process` object `Kill(true)` with bounded reap — no PID lookup, no
taskkill/global kill. Timeout knobs are range-checked; PowerShell 7 only.

Coordinator-independent checks this turn: official installer SHA256
`e8e264aca8bc34abdf592352bf09f986a85cdb96db0efba405ca9e149181fe61` (1,450,344
bytes), empty-placeholder and unknown-servicing preflight both fail closed.
PowerShell Parser, header/wrapper drift, actionlint and `git diff --check`
pass. **No Windows runtime claim**: Authenticode, real SDK installation and
GN/ninja/harness remain Not Verified until coordinator native CI exercises the
installer on a disposable runner. No source/DEPS/compiler pin changes; no
mirrored config test suite.

## Native Windows SDK 28000 prerequisite, 16 October 2026

Run 38966858843 passed pins/fetch and the prior toolchain env-scope gate, then
GN failed because `include\10.0.28000.0\um` is missing. The pinned Chromium
checkout hardcodes `SDK_VERSION = '10.0.28000.0'` in both
`build/vs_toolchain.py` and `build/toolchain/win/setup_toolchain.py`; a GN arg
cannot safely override both. Silent downgrade to 26100 is refused.

Microsoft's official downloads page lists **Windows SDK 10.0.28000.2957**
(September 2026) installer `https://go.microsoft.com/fwlink/?linkid=2382519`.
Coordinator downloaded the 1,450,344-byte `winsdksetup.exe` (under the 50MiB
cap) and pinned SHA256
`e8e264aca8bc34abdf592352bf09f986a85cdb96db0efba405ca9e149181fe61` with PE
product `Windows Software Development Kit - Windows 10.0.28000.2957` /
`Microsoft Corporation` in `webrtc-native/inventory/win-sdk-pins.json`.

`scripts/install-win-sdk.ps1` is the bounded CI prerequisite (run **before**
costly fetch): SHA256, Windows Authenticode **Valid** + Microsoft publisher,
documented `OptionId.DesktopCPPx86` / `OptionId.DesktopCPPx64` /
`OptionId.WindowsDesktopDebuggers` features, then file-level preflight of
x86/x64 headers, libs, `rc.exe`, and `Debuggers/**/dbghelp.dll`. Reboot
(3010) is not silent success. Existing complete SDK is retained only after
the same file-level preflight. Disposable runner install only; no Mac install,
no ISO, no vendor patch, no source/DEPS/compiler pin changes.

Mac coordinator checks: PowerShell Parser on install/build/fetch scripts,
header/wrapper drift, actionlint, `git diff --check`, valid manifest, and
local official installer SHA match. **Windows native acceptance remains Not
Verified** until a real CI run installs the pinned SDK and completes
GN/ninja/harness. No native pass claim.

## Native Windows build-process toolchain policy, 16 October 2026

Run38933830544 passed strict header drift and the pinned fetch, then failed
GN generation: the fresh build process lacked `DEPOT_TOOLS_WIN_TOOLCHAIN=0`
and selected the unavailable depot-managed VS toolchain. The build script now
sets that supported installed-SDK policy and `DEPOT_TOOLS_UPDATE=0` itself;
workflow environment agrees. Checkout Chromium clang-cl, source/DEPS/compiler
pins and all strict gates remain unchanged.

The coordinator invoked the actual old/new PowerShell scripts against a
nonexistent checkout in separate child processes. Old script exits1 at the
policy assertion; patched script exits0, with unrelated environment preserved
and no checkout/network mutation. The actual-script probe supplies evidence
without a new permanent test for this reversible build configuration change.
MiMo export verifies69 assistant records with
`xiaomi-token-plan-ams/mimo-v2.6-pro`, `high`. PowerShell parsing,
header/wrapper drift, actionlint and diff checks pass. Native Windows
GN/ninja/harness acceptance still requires the next CI run.

## Native Windows dependency-cache CI correction, 16 October 2026

Run38930677112 passed header drift, then failed fetching dependencies: pinned
`git_cache.Mirror` looked for `git.bat` on the Windows runner, where Git provides
`git.exe`. Both fetch scripts now explicitly disable the optional mirror cache
with supported `.gclient` `cache_dir = None`. Source, DEPS and compiler pins,
strict header comparison and hooks remain unchanged; no vendor patch or shim.

The coordinator reproduced the real pinned `Mirror.SetCachePath(None)` behavior
without Git subprocesses, verified LF/config preservation, parsed PowerShell,
and passed actionlint. Exported session metadata records48 assistant messages
using `xiaomi-token-plan-ams/mimo-v2.6-pro`, variant `high`. A fresh native Windows
run remains required; this configuration check does not establish Windows
WebRTC runtime acceptance or the media/admission/public relay adoption gate.

## Native Windows newline CI correction, 16 October 2026

Run38926181465 failed the strict generated-header byte comparison because the
Windows checkout converted the retained LF header to CRLF. Narrow Git attributes
now keep the native package/workflow LF; the generator and byte comparison remain
strict. Upstream fetch scripts append process-local LF Git settings without
replacing caller entries or changing source/dependency pins. The negative CRLF
probe uses a disposable package copy and leaves the tracked header intact.

Coordinator independently passed the newline/config probe, parsed all three
PowerShell scripts with `/tmp/hs-toolchain/pwsh/pwsh`, passed actionlint and diff
checks. Root Rust79-test/fmt/strict-Clippy evidence remains green. Export metadata
verifies the bounded CI repair as `xiaomi-token-plan-ams/mimo-v2.6-pro`, `high`.
A real Windows native rerun is still required; prior arm64/ASan/Swift/C# runtime
proof remains scoped to its tested platform. No C++/ABI behavior changed.

## Coordinator native WebRTC candidate, 16 October 2026

The coordinator reproduced the checked-in arm64 build and **100 native harness
checks**, rebuilt the bridge/harness ASan target and passed **100 checks**, and
compiled/ran the full Swift wrapper (**13 checks**) and C# P/Invokes (**16 checks**)
against the real shared library. Header/wrapper drift, actionlint and diff checks
pass. Core Rust tests (**79 passed**), format and strict Clippy pass. The final
Intel harness and shared library cross-build also passes; Intel runtime remains
Not Verified. ASan covers Helicoid sources, not all upstream archives.

Generated Ninja commands independently show static-mode defines on both the
static bridge and harness, and shared-export mode only on the DLL/dylib target.
Both platform scripts use one portable GN staging implementation. Only Windows
outputs are retained in the Windows artifact; .NET runtime build products are
ignored. The coordinator verified exported model metadata as
`xiaomi-token-plan-ams/mimo-v2.6-pro`, variant `high`.

Windows native CI is pending. Capture, endpoint admission, media, input and the
public relay adoption gate remain unavailable or Not Verified. This candidate
is a connection-only prerequisite, not a staged preview/checkpoint release.
No historical RustDesk/authority laboratory or production service was changed.

# BUILD-REPORT — hs-core (`modules/core/**`)

Updated: 13 October 2026; historical review-fix report dated10 October below
Agent: core build agent
Owned path: `modules/core/**` only
Product identity: **Helicoid** / **Helicoid Systems**; native roles
**Helicoid Manager** / **Helicoid Computer** (D15 confirmed). Durable release
package and service identifiers still require B01.

## E01 WebRTC connection proof (webrtc-native), 15 October 2026

Selected engine route is **native Google WebRTC**. Package `webrtc-native/`
pins Google WebRTC `d7862361c6c3942b5b96c8162ae4fa37666a2ea3` (DEPS SHA256
`d060df2421433efe13a0ab4f227174676f0b07f3c10a4be13b81d8dbe761a86f`) and
depot_tools `2fd34a8813b6f34336aad40976cc4223768177f8`. Invoked compiler is the
checkout Chromium clang 24.0.0git (LLVM `86922d51225db089fffb99475eefc4904f79e3c8`,
`llvmorg-24-init-7747-g62397f8b` subrev 31); GN 2576 / Ninja 1.12.1 from the
checkout CIPD paths. Host Apple clang 21 is metadata only.

**Verified (macOS arm64):** real two-peer PeerConnections, generated DTLS
certificates, offer/answer + ICE, product data channel both directions,
negotiated certificate from connected DTLS only, tampered-cert denial, handle
replacement/close invalidation, forged-handle rejection, two live engines,
free/release churn, slow-callback and timeout/late-callback cases.
Harness **100 checks, 0 failures**. ASan-instrumented bridge/harness (own
sources only; upstream archives reused) **100 checks, 0 failures, no ASan
errors**. Swift wrapper runtime (full wrapper source compile+run) vs
`libhs_webrtc_shared.dylib` **13/13**. C# wrapper runtime vs the same dylib
(.NET 10.0.401) **16/16**. Dynamic assertion counts; DLL exports verified. Cross-build
macOS x86_64 harness produced. `actionlint` 1.7.12 passes the Windows
workflow. Reproducible GN setup is checked in (`gn/BUILD.gn` +
`scripts/setup-gn-target.sh`) and pin-verified before build.

**Not Verified:** Windows native acceptance (workflow
`.github/workflows/webrtc-native-windows.yml` is the active path, pending real
CI), Intel runtime execution, full vendor ASan (only the hs-native bridge is
instrumented), capture/admission/media (explicitly unavailable), and full E01
adoption. The RustDesk laboratory under `engine-lab/` is retained unchanged
as historical evidence.

## Retained Windows laboratory bundle acceptance, 13 October 2026

[Native CI38317350914](https://github.com/Helicoid-Systems/core/actions/runs/38317350914) passes at exact code `155fff24605d4ae3beacd2b91986676ff8452c72`: **32 Rust tests**, **133 C checks** and **85 C# checks**, followed by the same **133 C /85 C# checks against the retained DLL copy**. All reports have zero failures; the retained DLL hash remains unchanged. Separate [domain/authority/header CI38317351049](https://github.com/Helicoid-Systems/core/actions/runs/38317351049) passes all five jobs.

The coordinator downloaded and independently verified the [unsigned laboratory bundle](https://github.com/Helicoid-Systems/core/actions/runs/38317350914/artifacts/11778571128): ZIP SHA256 `69f6dfddbb303bd7d61bca5daeea731313f4986896225925b339733782a34afe`, actual PE x64 `librustdesk.dll` (16958464 bytes, SHA256 `3cd453ecab4373e4e23b59fecc7f3c425758ba0ddd4a3ab7c62844887f8092cf`), all28 retained members against the bounded receipt, exact generated header, all27 DLL exports and all16 frozen source hashes. Independent PE import inspection finds no Flutter/Sciter dependency. The portable bundle checker also passes against these actual downloaded bytes; this local check proves integrity/metadata, while Windows runtime proof comes from native CI.

MiMo session `ses_ffe5ecde4effdffe4dZROL0HNu` has94 exported assistant records identifying only `xiaomi/mimo-v2.6-pro`; export SHA256 `dff012ad110c8c607989a318b42d5e007fb7100a3550525af71e5cde464786ca`. Coordinator checks include29 metadata/path/copy cases, independent dangling-link refusal and unchanged frozen source hashes.

**Verified:** retained inert native lifetime test bundle. **Unavailable:** connect, observation and channel binding; selected stock relay adoption remains Failed/Closed. Installed Windows11, product app linkage, actual capture/input, Intel runtime, signing, recovery and release acceptance remain **Not Verified**. The receipt supplies integrity evidence only and grants no release/update or connection authority. External MSVC/UCRT/.NET prerequisites remain documented, never installed by the helper.

## Retained exact tested-DLL lab bundle seam, 12 October 2026 (agent)

Historical [artifact 11754147189](https://github.com/Helicoid-Systems/core/actions/runs/38259987539/artifacts/11754147189) (acceptance at `e4fe20e40cda671535a20417a6a1bfa7eff6387d`) contains harness binaries and reports but **does not retain the tested `librustdesk.dll`**, so it cannot serve as a standalone inert lab test bundle. This revision closes that concrete packaging gap only; no product/media/transport adoption.

`build-windows-x64.ps1` gains a smallest post-success seam that copies the **exact** `librustdesk.dll` used by the C/C# harnesses into the owned output at the declared name beside the existing harness/runtime files (current relative layout; application-directory load; no DLL-search expansion) via `Copy-RetainedExactBytes`, which refuses directory/junction/link destinations before any copy and retains an identical regular file only after hash match. Import libraries are kept only as `librustdesk.dll.lib`/`librustdesk.lib`. The existing C and C# checks are re-run against the retained copy only (cargo target dir removed from `PATH`), producing required `harness-staged.txt`/`csharp-staged.txt`; original 32/133/85 reports are unchanged. The retained DLL is hashed before/after those runs.

`lab-bundle-receipt.json` (`hs-windows-lab-bundle-receipt/v1`) is a **bounded evidence/integrity record**, not a signed release/update manifest: lab source Git SHA, frozen upstream/hbb_common/Cargo.lock/vcpkg pins (vcpkg cross-checked to the workflow pin), `windows/x86_64` PE `8664`, ABI v2 / 27 exports set-equal to the retained header, SHA256+size for every member (256 MiB/member, 512 MiB total; only `pe/` and `csharp-lifetime-check/` subdirs), INERT UNSIGNED LAB claims with connect/observation/channel_binding **UNAVAILABLE**, and measured MSVC CRT / UCRT / .NET 10 prerequisites that are documented, never installed.

`check-windows-lab-bundle.ps1` fail-closes on missing receipt/DLL/staged reports, oversized/malformed receipt, path aliases, links/reparse, non-allowlist members, hash/size mismatch, non-x64 PE for native DLL / C harness EXE / C# apphost EXE (managed assembly may be AnyCPU), export/pin drift, and any signing or connect-available claim. Workflow success gate requires `librustdesk.dll`, `lab-bundle-receipt.json`, `harness-staged.txt`, `csharp-staged.txt` and runs the checker. Frozen patch/source pins/Cargo/header/descriptor/wrappers/harnesses/NativeDllGate are unchanged.

Local probes on Mac (PowerShell 7.6.6): scripts AST-parse; header/wrapper **PASS**; actionlint **PASS**; 29/29 cases green (real e4fe missing-DLL proof, path/receipt negatives, MissingStagedReports Required=true, 5 pure copy-helper conflict cases extracted from the real build script). **No synthetic PE/DLL fixtures and no local full-bundle positive acceptance.** Inventory `main_accepted_core_pin` renamed to `historical_main_pin_before_native_verification`; `accepted_base_core_pin=a8cbd2be948740030891be8a4f291c67adb687bf`. At agent completion, native verification was pending; the coordinator acceptance above supersedes that candidate status. Report: `/tmp/hs-production-20261012/engine-retained-windows-bundle-report.md`.

## Native Windows lifetime acceptance, 12 October 2026

Complete [native CI38259987539](https://github.com/Helicoid-Systems/core/actions/runs/38259987539) passes at exact code `e4fe20e40cda671535a20417a6a1bfa7eff6387d` on Windows Server2022. **32 Rust tests,133 linked C checks and85 C# lifetime checks** pass with zero failures. Actual x64 DLL build/27 exports/no Flutter-or-Sciter imports and16 frozen source hashes pass. Separate [core/authority/header CI38259987548](https://github.com/Helicoid-Systems/core/actions/runs/38259987548) passes all five jobs.

The coordinator independently inspects the downloaded [evidence archive](https://github.com/Helicoid-Systems/core/actions/runs/38259987539/artifacts/11754147189): published SHA256 `89f883cb7920c5fc886ea7c3c1cc249795d5fea93b9674b589f3620b197b0416`, ZIP integrity, both zero-failure harness reports, generated header bytes, exact27 exports and16 hashes matching the tested source. Harness executables are PE x64. The archive contains reports and harness binaries; the tested `librustdesk.dll` is not retained, so this is not an installable engine package.

This evidence-only revision preserves tested code. **Verified scope:** Windows inert ABI/lifetime, callbacks, close/drain and wrapper ownership. **Not Verified/unavailable:** installed Windows11/app linkage, admitted media/input/channel binding, public-route adoption, Intel runtime, signing and recovery/security review. Selected stock relay adoption remains Failed/Closed. Earlier entries below describe historical candidate states and failed runs.

## Native header checker encoding, 12 October 2026

[Native run 38248924582](https://github.com/Helicoid-Systems/core/actions/runs/38248924582) at `977c9f2` passes exact upstream/submodule/lock/patch/hash gates, then stops at retained source extraction in `check-header.py`. Unlike the generator and wrapper checker, that checker used the platform default text decoder. Extracting the same UTF-8 patch as CP1252 reproduces a different source hash. The checker now explicitly reads UTF-8 and writes UTF-8/LF temporary source; actual header bytes, exports and pin hashes remain unchanged. Fresh source/header and wrapper drift checks pass on Mac; actual Windows continuation is still required. Separate [core/authority CI 38248924476](https://github.com/Helicoid-Systems/core/actions/runs/38248924476) passes all platforms.

## Windows checkout line endings, 12 October 2026

[Native pipeline 38248418243](https://github.com/Helicoid-Systems/core/actions/runs/38248418243) at `d5601b8` stopped at the unchanged Cargo.lock hash gate. The actual Windows hash `580ba38e…` exactly matches CRLF conversion of the retained LF lock `b7ac324e…`; upstream attributes specify `* text=auto`. Disabling autocrlf alone leaves native checkout endings in effect. The coordinator reproduced both hashes through real Git checkout settings on disposable exact source, then configured both `core.autocrlf=false` and `core.eol=lf` only for CI Git commands. No source/lock/hash pin is changed or accepted after conversion. Fresh workflow validation passes; the next actual native run remains required. The separate domain/authority/header [CI 38248418152](https://github.com/Helicoid-Systems/core/actions/runs/38248418152) passes on this candidate, including all three authority platforms.

## Windows native engine pipeline candidate, 12 October 2026

The bounded MiMo package (`ses_ffe5ed38a7197ffeHXifAvKzPG`) exports only `xiaomi/mimo-v2.6-pro` assistant turns. New Windows-only C harness and a C# helper link the frozen wrapper/lifetime check against the actual pinned DLL. A separate 90-minute Windows x64 job installs declared MSVC/.NET/Python/Rust tools, clones exact RustDesk/hbb_common pins, retains Cargo.lock, installs upstream vcpkg overlays at the frozen baseline, runs actual hs_native tests and both linked harnesses, and records PE/tool/hash evidence. Production connect/observation/channel-binding remain unavailable; selected stock relay adoption remains failed/closed.

Coordinator review repaired callback drain/timeouts that could otherwise close still-used handles, made header output explicitly LF (no ABI/header change), scoped LF Git checkout configuration to the CI job, initialized runner-dependent paths inside a runner step, and corrected pin parsing to honor the existing multiline inventory while still rejecting malformed/duplicate required pins. The exact retained patch, header, descriptor, wrappers and Mac harness are unchanged. No authority/core domain code or Cargo changes.

Fresh coordinator checks: native header/wrapper drift **PASS**; all four PowerShell AST parses **PASS**; .NET10 helper build **0 warnings/errors**; actual PowerShell source pins, patch application and patched-file hashes on the exact source **PASS**. Reapplication, lock/source drift, malformed/traversal manifests and duplicate pins each refuse for their intended reason. These are artifact/tool checks on this Mac. **Native Windows build, Rust/C/C# execution and PE inspection remain Not Verified at publication**; main keeps accepted core `067de35` until applicable native gates pass. Real media, input, public transport, installed acceptance and signed release are not established.

## Windows .ps1 argument forwarding repair, 12 October 2026 (agent)

[Native run 38249512646](https://github.com/Helicoid-Systems/core/actions/runs/38249512646) at `e7c9d5f` passed exact source/submodule/lock pins, retained patch apply + all patched-file hashes, header/wrapper checks and actual pinned vcpkg manifest dependency installation, then failed before the Rust native build at `build-windows-x64.ps1` **check source pins** with `A positional parameter cannot be found that accepts argument 'D:\a\_temp\hs-engine-windows-ci\source'.` Log: `/tmp/hs-production-20261012/engine-e7c9-native-failed.log`.

Cause: `Invoke-Checked` splatted `@('-Upstream', $Upstream)` as a positional argument array into a PowerShell `.ps1`. Unlike a native exe argv, `'-Upstream'` was bound as a positional value for the mandatory `Upstream` parameter and the real path became an unbound extra positional. Repair: a distinct `Invoke-CheckedScript` helper uses a named hashtable splat (`@{ Upstream = $Upstream }`) for the two `.ps1` callees; `Invoke-Checked` argv arrays for cargo/python/cl/dotnet are unchanged, as are strict `Fail`/`$LASTEXITCODE` checks. No pin/hash/patch/header/wrapper/Cargo/ABI change.

Agent checks on Mac (PowerShell 7.6.6, real check scripts on `/tmp/hs-production-20261012/engine-source`): AST-isolated old wrapper reproduces the exact positional error; fixed wrapper green on exact pins and patched-file hashes; wrong HEAD, wrong Cargo.lock hash and wrong patched-file hash each still refuse; four-script AST parses pass; header/wrapper-contract drift checks pass; actionlint on `engine-windows.yml` passes. **Coordinator independent rerun required.** Native Windows 32-test / real C/C# harness / PE evidence remains **Not Verified** until CI passes. No commit/push.

The coordinator independently reproduced the old positional-binding failure,
passed both real pinned-source and patched-hash scripts through the fixed
helper, and verified refusals for a non-checkout and a real wrong-HEAD checkout.
All four PowerShell scripts parse; header/wrapper drift and Actionlint pass.
Sanitized export verifies all29 assistant records as `xiaomi/mimo-v2.6-pro`.
These portable script checks do not establish native Windows DLL execution.

## Windows C harness IPv6 SDK include repair, 12 October 2026 (agent)

[Native run 38253183124](https://github.com/Helicoid-Systems/core/actions/runs/38253183124) attempt2 at `1fb642c` passed exact pins/patch/header/wrapper/vcpkg, all 32 real hs_native Rust tests (`32 passed; 0 failed`), built the actual x64 DLL and verified all 27 `hs_exports` + PE imports, then failed first at MSVC C harness compile: `windows-harness.c(186): error C2065: 'PMIB_TCP6TABLE_OWNER_PID': undeclared identifier` (and the matching use at line 197). Log: `/tmp/hs-production-20261012/engine-1fb-native-attempt2.log`. Attempt1 HTTP 500 on a dependency step is not a code failure; prior native failures (CRLF checkout, header encoding, `.ps1` positional splat) remain historical.

Cause (Microsoft primary source, bounded download this turn): `shared/tcpmib.h` declares `MIB_TCP6TABLE_OWNER_PID` / `PMIB_TCP6TABLE_OWNER_PID` inside `#ifdef _WS2IPDEF_`. `um/WinSock2.h` includes `ws2def.h`, not `ws2ipdef.h`, so `winsock2.h` alone leaves the IPv6 owner types undeclared. `um/WS2tcpip.h` includes `winsock2.h` then `ws2ipdef.h`. `shared/Iprtrmib.h` includes `tcpmib.h`; `um/iphlpapi.h` includes `iprtrmib.h`. Microsoft Learn for `MIB_TCP6TABLE_OWNER_PID` documents include `Iphlpapi.h` and states `Tcpmib.h`/`Iprtrmib.h` must never be used directly.

Repair (smallest include change in `engine-lab/native/windows-harness.c` only): public `#include <ws2tcpip.h>` after `winsock2.h` and before `iphlpapi.h`; winsock2 still precedes windows.h. No direct tcpmib/iprtrmib include, no fake SDK guard/type. IPv6 retained (`PMIB_TCP6TABLE_OWNER_PID`, `AF_INET6`); query error/retry/allocation bounds, ABI, header, patch, frozen pins, wrappers, drivers, workflow and callback ownership unchanged.

Agent local checks on Mac (not MSVC): `check-header.py` **0**; `check-wrapper-contract.py` **0**; four PowerShell AST parses **0**; actionlint `engine-windows.yml` **0**. **MSVC C compile after the include repair and native Windows runtime remain Not Verified; actual Windows CI is the required red/green check.** No accepted main pin advance. Report: `/tmp/hs-production-20261012/engine-ipv6-sdk-header-report.md`.

Coordinator independently passes header/wrapper drift, four real PowerShell parses and Actionlint, confirms all frozen ABI/patch/wrapper/Mac harness bytes unchanged, and verifies 34 exported assistant model records as `xiaomi/mimo-v2.6-pro` (SHA256 `e390f40fa088b1162d0e6fd52f2d3f1ef70b7f764b2fa4fc4842da6f6d6efc02`). Microsoft SDK source independently confirms the include chain. These checks establish the reviewed source repair; actual native C/C# execution remains required.

## Historical domain-only review-fix report, 10 October 2026

The sections below preserve the original domain-only revision and its then-current gates. They are historical evidence, not current ABI, RustDesk-adoption or CI status; current acceptance is recorded above and in the engine inventory.

## Result

**VERIFIED** for the domain-library scope, including the coordinator review
findings: constructor-bypass deserialization and generation saturation are
fixed at the root, with failing-before/fresh-passing regression tests.

## Review findings addressed

| Finding | Root cause | Fix | Regression |
|---|---|---|---|
| `serde_json::from_str::<ComputerId>("\"\"")` returned `Ok` | `#[serde(transparent)]` derived `Deserialize` skipped constructors | Custom `Deserialize` on every bounded ID, `DisplayName`, `BoundedText`, `SearchQuery` calls the validating constructor | `review_regressions::empty_computer_id_deserialize_is_rejected` and related |
| `DesktopGeneration(u64::MAX).next()` saturated into the same generation | `saturating_add` reused current authority | `next() -> Option<Self>` (and `try_next`); exhaustion returns `None` / `Err`, never a reusable value | `generation_exhaustion_refuses_reuse`, `max_generation_minimize_still_tears_down_conservatively` |
| Action snapshot wire bypassed freeze invariants | Derived `Deserialize` filled private `target_ids` | `ActionSnapshot::from_parts` + custom `Deserialize` enforce non-empty bounded targets and valid deadline horizon | `action_snapshot_deserialize_rejects_zero_targets`, `..._rejects_invalid_horizon` |
| Out-of-scope action results accepted | No scope check on wire docs | `ActionSnapshotDoc` rejects results outside frozen targets (`ReasonCode::ComputerOutOfScope`) | `action_doc_rejects_out_of_scope_results`, `action_doc_wire_rejects_out_of_scope_results` |
| Unknown envelope schema versions accepted | No version gate | `SnapshotEnvelope` `Deserialize` rejects `schema_version != 1` | `envelope_rejects_unknown_schema_version` |
| Unbounded JSON body | No parse entry point | `snapshot::parse_snapshot_json` bounds `MAX_SNAPSHOT_JSON_BYTES` and is the only supported entry | `body_size_is_bounded_at_parse_entry` |
| Generation exhaustion during minimize/share teardown | Saturating counter | Minimize still tears down conservatively (`generation_fenced: None`); share branch/distribution stop independent of generation; new authority bound to an exhausted generation is refused | `max_generation_minimize_still_tears_down_conservatively`, `share_teardown_at_max_generation_is_conservative` |
| Schema not labeled as development format | Wording implied a settled protocol | Schema + README label it a **development snapshot format**, not settled media/auth protocol | Schema title/description; `snapshot` module docs |
| Product names / D18 / D21 stale | Report said naming/D18 awaited user | Updated to Helicoid / Helicoid Systems; D18 and D21 recorded as confirmed | README + this report |
| lib.rs consumer statement | Implied apps link Rust | States intended native consumers; apps do not link this crate yet | `src/lib.rs` header |
| No independent Rust CI | Missing | `.github/workflows/ci.yml` runs fmt/test/clippy with `--locked` from official `actions/checkout` and `dtolnay/rust-toolchain` | Workflow file present under owner tree |

## Modified files (this revision)

All under `modules/core/**`:

| Path | Change |
|---|---|
| `src/id.rs` | Validating `Deserialize` for bounded IDs/DisplayName/BoundedText; generation `next() -> Option` |
| `src/action.rs` | `ActionSnapshotParts`, `from_parts`, custom Serialize/Deserialize with freeze invariants |
| `src/inventory.rs` | Validating `Deserialize` for `SearchQuery` |
| `src/snapshot.rs` | Development-format labeling; envelope version gate; `parse_snapshot_json` / `to_snapshot_json`; in-scope result checks |
| `src/interaction.rs` | Generation exhaustion: minimize teardown without reusable fence; `bump_source_generation -> Result`; refuse new authority on exhausted desktop generation; `BeginInteraction.initial_generation` |
| `src/lib.rs` | Helicoid naming; intended native consumers; new exports |
| `schemas/hs-core-snapshot-v1.schema.json` | Development snapshot format label |
| `README.md` | Helicoid naming; D18/D21 confirmed; validation boundary; CI note |
| `tests/review_regressions.rs` | New: failing-before/fresh-passing review regressions |
| `tests/interaction_lifecycle.rs` | Updated for `initial_generation` field |
| `examples/repro_review.rs` | Coordinator reproducer converted to a fixed-behavior check |
| `.github/workflows/ci.yml` | New: independent fmt/test/clippy CI with lockfile |

No files outside `modules/core/**` were created or modified. No deletion, no
global install, no git init/commit/push.

## Commands and results

Toolchain: `rustc 1.99.0` / `cargo 1.99.0` at `/tmp/hs-toolchain`
(`CARGO_HOME=/tmp/hs-toolchain/cargo`, `RUSTUP_HOME=/tmp/hs-toolchain/rustup`,
dedicated `CARGO_TARGET_DIR=/tmp/hs-core-target`).

| Command | Exit | Result |
|---|---|---|
| `cargo fmt` | 0 | Formatted |
| `cargo fmt -- --check` | 0 | Clean |
| `cargo clippy --all-targets -- -D warnings` | 0 | Clean |
| `cargo test` | 0 | **79 passed, 0 failed** |

Test breakdown after the fix:

| Suite | Tests | Result |
|---|---|---|
| `src/*.rs` unit | 35 | ok |
| `tests/action_snapshots.rs` | 5 | ok |
| `tests/engine_and_console.rs` | 8 | ok |
| `tests/interaction_lifecycle.rs` | 10 | ok |
| `tests/inventory_selection.rs` | 6 | ok |
| `tests/review_regressions.rs` | 15 | ok |

### Original defects (was red, now green)

```
// before
serde_json::from_str::<ComputerId>("\"\"") == Ok("")   // constructor bypass
DesktopGeneration(u64::MAX).next() == Some(MAX)        // reusable authority

// after (review_regressions.rs + examples/repro_review.rs)
empty_computer_id_deserialize_is_rejected ... ok
generation_exhaustion_refuses_reuse ... ok
max_generation_minimize_still_tears_down_conservatively ... ok

$ cargo run --example repro_review
ok: empty ComputerId deserialize is rejected
ok: exhausted DesktopGeneration refuses reuse
repro_review: both review defects are fixed
```

## Confirmed product decisions reflected

- **D15**: Helicoid display name; Helicoid Systems company identity; native
  roles Helicoid Manager / Helicoid Computer. Durable package/service IDs
  remain B01 outputs (not invented here).
- **D18** (confirmed): reconnecting included eligible computers resume
  view-only after fresh admission; All mode includes newly authorized eligible
  inventory; explicit-ID inclusion and existing action snapshots never expand
  silently. Implemented in `inventory::OverviewState`.
- **D21** (confirmed): closing a file request refuses new submissions and
  retains completed files; replacement requires explicit confirmation. File
  request storage is a server responsibility; core supplies the immutable
  target-snapshot and result semantics that flow depends on.

## Explicitly not proved here (unverified gates)

Synthetic domain tests cannot substitute for platform evidence.

| Gate / scenario | Status | Why |
|---|---|---|
| E01 RustDesk adoption | **Pending** | `rustdesk_pending` records RD01–RD12 as all Pending. |
| E03 protocol / native ABI | **Not started** | No C ABI exported. Media/auth grant protocol remains unadopted. |
| E04 capture / input / attention on real OS | **Not run** | No capture, input injection, or permission probing in this crate. |
| E06 numeric limits / performance budgets | **Candidates only** | Bounds in `bounds.rs` are engineering candidates awaiting measurement. |
| V01–V04, V07–V11, V13–V31 | **Not run** | Require native apps, real endpoints, and OS effects. |
| V05, V06, V08, V12, V34, V37, V40, V41 | **Synthetic only** | Domain rules covered by unit/integration tests; no installed OS evidence. |
| V33 independent build/CI | **Partial** | Local `cargo build/test/clippy` succeeded alone. Workflow file added; no CI run log yet. |
| V39–V51 | **Not run** | Installer, recovery, security-floor, icon, and deployment proofs are outside this crate. |

## Remaining uncertainties

1. **B01 durable release package/service identifiers** — still required;
   `Cargo.toml` keeps `publish = false` and no invented repository URL.
2. **E06 frozen numeric bounds** — `bounds.rs` values remain labeled
   candidates.
3. **E03 reason-code wire mapping** — `ReasonCode::as_str` is the domain-local
   stable name, not a frozen transport enum.
4. **RustDesk feasibility** — RD01–RD12 all Pending against research snapshot
   `001b0e96173cea4e49f9f7a67bea95a177dd1de3` (inspected 9 October 2026, not
   an adopted pin).
5. **Custom crypto / grants** — intentionally absent.

## Design notes

- Ownership of `modules/core/**` is exclusive.
- Standard library first. Only `serde` / `serde_json` for the development
  snapshot interchange.
- No `unsafe`, no C ABI, no networking, no filesystem, no clock — timestamps
  are host-supplied `TimestampMs`.
- Every refusal carries a `ReasonCode`. Generation exhaustion is an honest
  `Option`/`Result`, never a saturating reuse.
- Untrusted JSON enters only through `snapshot::parse_snapshot_json`.
- `development-fixtures` is a named cargo feature; fixtures are labeled and
  are not production pixels.
