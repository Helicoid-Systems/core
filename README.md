# hs-core

The selected native engine is Google WebRTC. `webrtc-native/` implements the
ABI-3 connection subset against a pinned upstream revision. Coordinator checks
on macOS arm64 pass 142 native tests, 142 own-bridge AddressSanitizer tests,
22 Swift checks and 16 C# checks. Its separate loopback TURN/TLS prerequisite
connects both peers using exact certificate pins and REST authentication.

Windows baseline CI [39037906193](https://github.com/Helicoid-Systems/core/actions/runs/39037906193)
passed 142 native and 16 C# checks with inspected unsigned x64 artifacts.
Windows TURN runtime, Intel runtime, public TCP443 and installed platform
acceptance remain Not Verified. Product capture, admission and media are still
disabled; bounded native video primitives exist but are not wired through the
Manager and endpoint applications.
See `webrtc-native/README.md` and `BUILD-REPORT.md` for the evidence boundaries.
The historical RustDesk laboratory remains under `engine-lab/`.

Shared Helicoid computer-monitoring domain contracts for Helicoid Systems'
**Helicoid Manager** / **Helicoid Computer** product.

This is an independently buildable Rust library. It owns `modules/core/**` only
and has no sibling path dependencies.

## Intended consumers

The intended native consumers are the Helicoid Manager and Helicoid Computer
apps: Swift on macOS (Intel and Apple Silicon) and WinUI 3 / C# on Windows,
plus the shared Rust coordination server. Those apps do **not** currently link
this Rust crate directly; they consume the versioned development snapshot
interchange in `snapshot` and the contracts documented here. Native ABI
exports are intentionally absent until E03 can prove lifetime/panic/bounds
rules.

## What it is

Pure domain and lifecycle state:

- typed bounded identifiers and capability evaluations
- inventory inclusion, displayed filters, and temporary action selection
- immutable action snapshots and a per-target result journal
- OS physical-console selection, desktop generations, preview readiness
- observation/control lifecycle (several observers, one controller)
- focus / minimize / desktop-change / expiry teardown rules
- a fail-closed engine-unavailable boundary

## What it is not

These contracts are **development semantics**. They are **not** signed grants
and **not** a cryptographic wire format.

- No custom cryptography, capture, input injection, networking, or persistence.
- Media and authentication grant protocols remain unadopted.
- **Selected route (E01): Google WebRTC** — `webrtc-native/` holds the pinned
  native connection proof and ABI-3 subset (init / negotiation / channel-evidence
  / drain). The RustDesk `engine-lab/` is historical and is not the selected
  route. `engine_adoption_pending` tracks the production gates still open.
- `webrtc-native` provides bounded send/receive video primitives and a
  short-lived channel-bound lease, but it does not provide platform capture,
  product grant verification, an integrated admission workflow, or input.
  Capture, admission, and media capability bits stay unset until the host apps
  connect these primitives and pass end-to-end acceptance.
- Deterministic unit tests verify domain rules only. They are **not** real
  platform proof of capture, input, installation, or performance.

## Build and test

Independent of any sibling checkout:

```bash
cargo build
cargo test
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
```

CI: `.github/workflows/ci.yml` runs fmt/test/clippy with the package lockfile
(`--locked`) from official checkout and Rust toolchain actions.

Durable release package and service identifiers still require B01. Confirmed
product identity: Helicoid / Helicoid Systems; native role names Helicoid
Manager and Helicoid Computer.

## Confirmed product rules reflected here

- **D18** (confirmed): reconnecting included eligible computers resume
  view-only after fresh admission; All mode includes newly authorized eligible
  inventory; explicit-ID inclusion and existing action snapshots never expand
  silently.
- **D21** (confirmed): closing a file request refuses new submissions and
  retains completed files. Replacing a submission requires explicit
  confirmation. (File-request domain lives with the server; core keeps the
  target-snapshot and result semantics those flows depend on.)
- **D15**: display name Helicoid, company Helicoid Systems. Durable package
  and service identifiers remain B01 outputs.

## Module map

| Concern | Module |
|---|---|
| Identifiers, generations, bounded text | `id` |
| Numeric bounds (E06 candidates) | `bounds` |
| Reason codes | `reason` |
| Typed errors | `error` |
| Capabilities, computer scope, access assignment | `capability` |
| Inventory / inclusion / displayed / selection | `inventory` |
| Immutable action snapshots and results | `action` |
| Console selection, generations, engine health | `console` |
| Observation / control / sharing / teardown | `interaction` |
| Development snapshot interchange (bounded parse) | `snapshot` |
| Opt-in development fixtures (`development-fixtures`) | `development` |
| Pending engine adoption checklist | `engine_adoption_pending` |

## Validation and trust boundary

Untrusted JSON must enter through `snapshot::parse_snapshot_json`, which:

- bounds the body size (`MAX_SNAPSHOT_JSON_BYTES`)
- rejects unknown `schema_version` values
- deserializes bounded IDs, display names, bounded text, and search queries
  through their validating constructors (no constructor bypass)
- rejects action snapshots with zero/oversized target collections or an
  invalid deadline horizon
- rejects action results that fall outside the frozen target scope

Generation counters never saturate into reusable authority. Exhaustion
refuses new authority and still permits safety teardown.

## Key separations

The overview keeps five state objects separate (ui.md selection rules):

1. Authorized inventory
2. Monitoring inclusion (All or explicit IDs)
3. Displayed IDs (inclusion after search/status filters)
4. Temporary action selection
5. Admitted streams (in `interaction`, not a boolean)

New bulk actions target selected displayed IDs, or all displayed IDs when
nothing is selected. A zero-sized target set cannot dispatch. Opening an action
composer freezes its computer IDs; later inventory/group/search changes cannot
expand that snapshot.

D19: several authorized observers coexist; one controller owns a computer.
D24: minimizing releases control and keeps viewing; restore requires explicit
Take Control. Focus loss stops forwarding and releases held input without
ending the lease. Desktop change, expiry, and revocation tear down access.

D26: version 1 monitors only the physical/primary console. RDP, background, and
virtual sessions are never selected as fallback. A session number is not
reusable authority — generations fence late work.

D25: overview previews use the endpoint-reported primary display of the current
layout generation. A missing primary display produces a named readiness state
and is never silently substituted.

D30: only the sharing owner or scoped authorized IT can explicitly stop a
receiving presentation. Computer-user dismissal attempts cannot end an admitted
branch. Automatic safety teardown remains effective.

## JSON schema

`schemas/hs-core-snapshot-v1.schema.json` is the **development** snapshot
format for inventory/status, overview scope, and action snapshot interchange
with the intended native consumers. It is not a settled media or authentication
grant protocol; those remain unadopted.

## Development fixtures

The `development-fixtures` cargo feature is a named opt-in. It provides
deterministic inventory entries labeled as fixtures. They are never production
pixels and must never be shown as live previews.

## Relationship to proof gates

Engineering gates E01–E08 and verification scenarios V01–V51 remain explicit.
This crate can satisfy domain-logic slices of V05/V06/V08/V12/V37/V40/V41 in
synthetic form only. Real capture, input, installation, and performance claims
require the platform evidence those scenarios demand.

`webrtc-native` holds a **loopback lab** TURN/TLS connection prerequisite
(REST auth, PEM and SHA-256 pin, causal verifier diagnostics). That boundary is
observed evidence only — not product pin/route acceptance, not public :443, and
not a production authorization lease. See `BUILD-REPORT.md` for the exact
observed checks and remaining Not Verified gates.
