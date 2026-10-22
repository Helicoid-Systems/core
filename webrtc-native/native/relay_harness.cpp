// relay_harness.cpp -- E01 bounded TURN/TLS relay-only connection proof.
//
// Separate lab harness. Uses hs_peer_create_relay with exact certificate
// trust, proves selected relay/TLS transport from native stats, exchanges
// byte-exact product messages both directions, and fail-closes the negative
// scenarios (wrong cert, wrong credentials, unavailable relay, wrong host).
//
// Credentials are read from a 0600 file path argument and never printed.
// Product capture/admission/media integration remains unavailable; bounded
// native video primitives are covered by the separate connection harness.
//
// Usage:
//   hs_webrtc_relay_harness <scenario> <config-file>
// Scenarios:
//   validate     config rejection checks (no network)
//   positive     two peers through local coturn TLS/TCP relay
//   wrong-cert   trust pin mismatch must reject TLS (no direct fallback)
//   wrong-cred   wrong TURN password must fail (no direct fallback)
//   no-relay     unreachable TURN must fail (no direct fallback)
//   wrong-host   host/trust mismatch must fail hostname or pin

#include "hs_webrtc.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

static int failures = 0;
static int checks = 0;

static void check(int cond, const char* name) {
  checks++;
  if (cond) {
    std::printf("ok   %s\n", name);
  } else {
    failures++;
    std::printf("FAIL %s\n", name);
  }
}

static void check_status(uint32_t got, uint32_t want, const char* name) {
  checks++;
  if (got == want) {
    std::printf("ok   %s\n", name);
  } else {
    failures++;
    std::printf("FAIL %s (got %u want %u)\n", name, got, want);
  }
}

static bool wait_until(bool (*pred)(void*), void* ctx, int timeout_ms) {
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    if (pred(ctx)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return pred(ctx);
}

struct PeerCtx {
  hs_peer* p;
};

static bool channel_open_pred(void* ctx) {
  auto* c = static_cast<PeerCtx*>(ctx);
  uint32_t st = 0;
  if (hs_peer_state(c->p, &st) != HS_STATUS_OK) return false;
  return st == HS_PEER_STATE_CHANNEL_OPEN || st == HS_PEER_STATE_CONNECTED;
}

static bool exchange_ice(hs_peer* a, hs_peer* b, int timeout_ms) {
  char buf[HS_MAX_SDP_BYTES];
  size_t len = 0;
  size_t candidates = 0;
  bool accepted = true;
  bool a_complete = false;
  bool b_complete = false;
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline &&
         (!a_complete || !b_complete)) {
    bool moved = false;
    auto poll = [&](hs_peer* local, hs_peer* remote, bool* complete,
                    const char* poll_description,
                    const char* add_description) {
      while (!*complete) {
        const uint32_t poll_status =
            hs_peer_poll_ice(local, buf, sizeof buf, &len);
        if (poll_status == HS_STATUS_EXHAUSTED) {
          *complete = true;
          break;
        }
        if (poll_status == HS_STATUS_TIMEOUT) break;
        if (poll_status != HS_STATUS_OK) {
          check_status(poll_status, HS_STATUS_OK, poll_description);
          accepted = false;
          *complete = true;
          break;
        }

        const uint32_t add_status = hs_peer_add_ice(remote, buf, len);
        if (add_status != HS_STATUS_OK) {
          check_status(add_status, HS_STATUS_OK, add_description);
          accepted = false;
        }
        ++candidates;
        moved = true;
      }
    };
    poll(a, b, &a_complete, "relay peer A ICE poll succeeds",
         "relay peer B accepts trickled ICE candidate");
    poll(b, a, &b_complete, "relay peer B ICE poll succeeds",
         "relay peer A accepts trickled ICE candidate");
    if (!moved) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
  if (!a_complete || !b_complete) {
    std::printf("relay ICE gathering deadline: A=%d B=%d candidates=%zu\n",
                a_complete, b_complete, candidates);
  }
  return a_complete && b_complete && accepted;
}

static bool negotiate(hs_peer* a, hs_peer* b) {
  // Match the proven 142-check harness path: offer/answer via create + set_remote
  // only. set_local is unused by the working local factory path (returns STATE).
  char offer[HS_MAX_SDP_BYTES];
  size_t offer_len = 0;
  char answer[HS_MAX_SDP_BYTES];
  size_t answer_len = 0;
  uint32_t st;
  st = hs_peer_create_offer(a, offer, sizeof offer, &offer_len);
  if (st != HS_STATUS_OK) {
    std::printf("  negotiate: create_offer A st=%u\n", st);
    return false;
  }
  const char* otype = "offer";
  st = hs_peer_set_remote(b, otype, 5, offer, offer_len);
  if (st != HS_STATUS_OK) {
    std::printf("  negotiate: set_remote B(offer) st=%u\n", st);
    return false;
  }
  st = hs_peer_create_answer(b, answer, sizeof answer, &answer_len);
  if (st != HS_STATUS_OK) {
    std::printf("  negotiate: create_answer B st=%u\n", st);
    return false;
  }
  const char* atype = "answer";
  st = hs_peer_set_remote(a, atype, 6, answer, answer_len);
  if (st != HS_STATUS_OK) {
    std::printf("  negotiate: set_remote A(answer) st=%u\n", st);
    return false;
  }
  return true;
}

static std::map<std::string, std::string> read_config(const char* path) {
  std::map<std::string, std::string> out;
  std::ifstream in(path);
  if (!in) return out;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    out[line.substr(0, eq)] = line.substr(eq + 1);
  }
  return out;
}

static bool parse_hex_sha(const std::string& hex, uint8_t out[32]) {
  if (hex.size() != 64) return false;
  for (int i = 0; i < 32; i++) {
    unsigned v = 0;
    if (std::sscanf(hex.c_str() + i * 2, "%2x", &v) != 1) return false;
    out[i] = static_cast<uint8_t>(v);
  }
  return true;
}

static std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

struct TurnCfg {
  hs_turn_tls_config raw{};
  std::string host, user, pass, pem;
  uint8_t sha[32] = {0};
  bool ok = false;
};

static TurnCfg build_cfg(const std::map<std::string, std::string>& kv) {
  TurnCfg t;
  t.host = kv.count("host") ? kv.at("host") : "";
  t.user = kv.count("username") ? kv.at("username") : "";
  t.pass = kv.count("password") ? kv.at("password") : "";
  t.raw.struct_size = sizeof(hs_turn_tls_config);
  t.raw.version = HS_TURN_CONFIG_VERSION;
  t.raw.host = t.host.c_str();
  t.raw.host_len = static_cast<uint32_t>(t.host.size());
  t.raw.port = kv.count("port") ? static_cast<uint32_t>(std::strtoul(
                                      kv.at("port").c_str(), nullptr, 10))
                                : 0;
  t.raw.username = t.user.c_str();
  t.raw.username_len = static_cast<uint32_t>(t.user.size());
  t.raw.password = t.pass.c_str();
  t.raw.password_len = static_cast<uint32_t>(t.pass.size());

  if (kv.count("trust_pem_path") && !kv.at("trust_pem_path").empty()) {
    t.pem = read_file(kv.at("trust_pem_path"));
    t.raw.trust_pem = t.pem.c_str();
    t.raw.trust_pem_len = static_cast<uint32_t>(t.pem.size());
  } else if (kv.count("trust_sha256_hex")) {
    // Trust is used exactly as supplied; the lab runner owns positive vs
    // wrong-pin cases. Never silently "fix" a pin.
    std::string hex = kv.at("trust_sha256_hex");
    if (parse_hex_sha(hex, t.sha)) {
      t.raw.trust_sha256 = t.sha;
      t.raw.trust_sha256_len = 32;
    }
  }
  t.ok = true;
  return t;
}

static int run_validate(hs_engine* eng) {
  std::printf("scenario validate (no network)\n");
  const std::string host = "127.0.0.1";
  const std::string user = "labuser";
  const std::string pass = "labpass";
  const std::string bad_pem =
      "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n";
  hs_turn_tls_config base{};
  base.struct_size = sizeof(hs_turn_tls_config);
  base.version = HS_TURN_CONFIG_VERSION;
  base.host = host.c_str();
  base.host_len = static_cast<uint32_t>(host.size());
  base.port = 5349;
  base.username = user.c_str();
  base.username_len = static_cast<uint32_t>(user.size());
  base.password = pass.c_str();
  base.password_len = static_cast<uint32_t>(pass.size());
  hs_peer* p = nullptr;

  // Null / wrong size / wrong version.
  check_status(hs_peer_create_relay(eng, nullptr, &p), HS_STATUS_NULL,
               "null config rejected");
  hs_turn_tls_config bad = base;
  bad.struct_size = 0;
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "bad struct_size rejected");
  bad = base;
  bad.version = 99;
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "bad version rejected");

  // Host form: URI metacharacters / control / NUL.
  std::string evil = "127.0.0.1?transport=udp";
  bad = base;
  bad.host = evil.c_str();
  bad.host_len = static_cast<uint32_t>(evil.size());
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "host URI metachar rejected");
  std::string with_nul("127.0.0.1", 9);
  with_nul.push_back('\0');
  with_nul += "x";
  bad = base;
  bad.host = with_nul.data();
  bad.host_len = static_cast<uint32_t>(with_nul.size());
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "host embedded NUL rejected");
  std::string with_ctrl = "127.0.0.";
  with_ctrl.push_back('\x01');
  with_ctrl += "1";
  bad = base;
  bad.host = with_ctrl.c_str();
  bad.host_len = static_cast<uint32_t>(with_ctrl.size());
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "host control char rejected");

  // Trust pointer/length consistency + malformed PEM.
  bad = base;
  bad.trust_pem = bad_pem.c_str();
  bad.trust_pem_len = static_cast<uint32_t>(bad_pem.size());
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "malformed PEM rejected before peer");
  bad.trust_pem = nullptr;
  bad.trust_pem_len = 16;
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "pem ptr/len mismatch rejected");
  uint8_t zsha[32] = {0};
  bad = base;
  bad.trust_sha256 = zsha;
  bad.trust_sha256_len = 32;
  bad.trust_pem = bad_pem.c_str();
  bad.trust_pem_len = static_cast<uint32_t>(bad_pem.size());
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "dual trust mode rejected");
  bad = base;
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_INVALID,
               "missing trust rejected");
  bad = base;
  bad.trust_sha256 = zsha;
  bad.trust_sha256_len = 16;
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_BOUNDS,
               "short sha length rejected");

  // Overflow bounds.
  bad = base;
  bad.host_len = HS_MAX_TURN_HOST_BYTES + 1;
  check_status(hs_peer_create_relay(eng, &bad, &p), HS_STATUS_BOUNDS,
               "host overflow rejected");

  std::printf("validate complete\n");
  return failures == 0 ? 0 : 1;
}

static int run_positive(hs_engine* eng, const std::map<std::string, std::string>& kv) {
  std::printf("scenario positive (relay-only TLS/TCP)\n");
  TurnCfg cfg = build_cfg(kv);
  if (!cfg.ok) {
    check(0, "config loaded");
    return 1;
  }
  hs_peer* a = nullptr;
  hs_peer* b = nullptr;
  uint32_t st = hs_peer_create_relay(eng, &cfg.raw, &a);
  if (st == HS_STATUS_UNAVAILABLE) {
    // Wrong build mode: exclusive pin not compiled in. Fail closed.
    check(0, "exclusive pin build mode (create_relay available)");
    return 1;
  }
  check_status(st, HS_STATUS_OK, "peer A relay create");
  st = hs_peer_create_relay(eng, &cfg.raw, &b);
  check_status(st, HS_STATUS_OK, "peer B relay create");
  if (!a || !b) return 1;

  // Match proven 142 harness: only initiator A creates the product channel.
  // Receiver B accepts via OnDataChannel observer. Dual create yields two
  // independent SCTP channels and never delivers messages.
  check_status(hs_channel_create(a, HS_PRODUCT_CHANNEL_LABEL,
                                 std::strlen(HS_PRODUCT_CHANNEL_LABEL)),
               HS_STATUS_OK, "peer A product channel");

  check(negotiate(a, b), "offer/answer exchange");
  check(exchange_ice(a, b, 15000),
        "relay ICE candidates were exchanged through gathering completion");

  PeerCtx ca{a}, cb{b};
  bool a_open = wait_until(channel_open_pred, &ca, 20000);
  bool b_open = wait_until(channel_open_pred, &cb, 20000);
  check(a_open, "peer A channel/connected");
  check(b_open, "peer B channel/connected");
  if (!a_open || !b_open) return 1;

  // DTLS evidence + verified channel (negotiated cert).
  // Both peers must have a connected DTLS path before verified acquire.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  const char msg_before_pin[] = "hs-relay-before-pin";
  uint8_t rbuf[HS_MAX_MSG_BYTES];
  uint32_t rlen = 0;
  check_status(hs_channel_send(
                   a, reinterpret_cast<const uint8_t*>(msg_before_pin),
                   static_cast<uint32_t>(std::strlen(msg_before_pin))),
               HS_STATUS_HANDSHAKE, "unverified relay send denied");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_HANDSHAKE, "unverified relay receive denied");

  // Negotiated peer certificate evidence + opaque verified-channel handles
  // (same contract as proven 142 harness). Caller fingerprint is not identity.
  uint8_t cert_a[HS_MAX_CERT_PEM_BYTES];
  uint8_t cert_b[HS_MAX_CERT_PEM_BYTES];
  uint32_t cert_a_len = 0, cert_b_len = 0;
  check_status(hs_peer_local_cert_export(a, cert_a, sizeof cert_a, &cert_a_len),
               HS_STATUS_OK, "peer A local cert exported");
  check_status(hs_peer_local_cert_export(b, cert_b, sizeof cert_b, &cert_b_len),
               HS_STATUS_OK, "peer B local cert exported");
  check(cert_a_len > 0 && cert_b_len > 0, "local certs non-empty");
  check_status(
      hs_peer_expected_cert_set(a, reinterpret_cast<const char*>(cert_b),
                                cert_b_len),
      HS_STATUS_OK, "A expected cert = B local cert");
  check_status(
      hs_peer_expected_cert_set(b, reinterpret_cast<const char*>(cert_a),
                                cert_a_len),
      HS_STATUS_OK, "B expected cert = A local cert");
  hs_verified_channel* va = nullptr;
  hs_verified_channel* vb = nullptr;
  check_status(hs_verified_channel_acquire(a, &va), HS_STATUS_OK,
               "A verified-channel acquire");
  check(va != nullptr, "A verified handle issued");

  check_status(hs_channel_send(
                   a, reinterpret_cast<const uint8_t*>(msg_before_pin),
                   static_cast<uint32_t>(std::strlen(msg_before_pin))),
               HS_STATUS_OK, "verified relay sender reaches unverified peer");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_HANDSHAKE, "unverified relay peer drops early data");
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  check_status(hs_verified_channel_acquire(b, &vb), HS_STATUS_OK,
               "B verified-channel acquire");
  check(vb != nullptr, "B verified handle issued");
  uint8_t binding_a[HS_MAX_CHANNEL_BINDING_BYTES];
  uint8_t binding_b[HS_MAX_CHANNEL_BINDING_BYTES];
  uint32_t binding_a_len = 0;
  uint32_t binding_b_len = 0;
  check_status(hs_verified_channel_binding_export(
                   va, binding_a, sizeof binding_a, &binding_a_len),
               HS_STATUS_OK, "relay A exports its DTLS/SCTP channel binding");
  check_status(hs_verified_channel_binding_export(
                   vb, binding_b, sizeof binding_b, &binding_b_len),
               HS_STATUS_OK, "relay B exports its DTLS/SCTP channel binding");
  check(binding_a_len > 0 && binding_a_len == binding_b_len &&
            std::memcmp(binding_a, binding_b, binding_a_len) == 0,
        "relay peers derive the same exact product-channel binding");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_EXHAUSTED, "relay early data was dropped");

  const char msg_ab[] = "hs-relay-ab";
  const char msg_ba[] = "hs-relay-ba";
  check_status(hs_channel_send(a, reinterpret_cast<const uint8_t*>(msg_ab),
                               static_cast<uint32_t>(std::strlen(msg_ab))),
               HS_STATUS_OK, "send verified A->B");
  check_status(hs_channel_send(b, reinterpret_cast<const uint8_t*>(msg_ba),
                               static_cast<uint32_t>(std::strlen(msg_ba))),
               HS_STATUS_OK, "send verified B->A");
  bool got_ab = false, got_ba = false;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < deadline && (!got_ab || !got_ba)) {
    if (!got_ab &&
        hs_channel_poll(b, rbuf, sizeof rbuf, &rlen) == HS_STATUS_OK) {
      got_ab = rlen == std::strlen(msg_ab) &&
               std::memcmp(rbuf, msg_ab, rlen) == 0;
    }
    if (!got_ba &&
        hs_channel_poll(a, rbuf, sizeof rbuf, &rlen) == HS_STATUS_OK) {
      got_ba = rlen == std::strlen(msg_ba) &&
               std::memcmp(rbuf, msg_ba, rlen) == 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  check(got_ab, "byte-exact verified A->B product message");
  check(got_ba, "byte-exact verified B->A product message");
  {
    uint8_t exported[HS_MAX_CERT_PEM_BYTES];
    uint32_t elen = 0;
    check_status(hs_verified_channel_export(va, exported, sizeof exported,
                                            &elen),
                 HS_STATUS_OK, "A export negotiated cert");
    check(elen == cert_b_len &&
              std::memcmp(exported, cert_b, elen) == 0,
          "A exported cert equals B local cert (negotiated)");
    elen = 0;
    check_status(hs_verified_channel_export(vb, exported, sizeof exported,
                                            &elen),
                 HS_STATUS_OK, "B export negotiated cert");
    check(elen == cert_a_len &&
              std::memcmp(exported, cert_a, elen) == 0,
          "B exported cert equals A local cert (negotiated)");
    // Wrong expected cert must be denied (not caller fingerprint authority).
    std::string tampered(reinterpret_cast<char*>(cert_a), cert_a_len);
    if (tampered.size() > 40) {
      tampered[40] = (tampered[40] == 'A') ? 'B' : 'A';
    }
    check_status(hs_peer_expected_cert_set(a, tampered.c_str(), tampered.size()),
                 HS_STATUS_OK, "A set tampered expected cert");
    hs_verified_channel* bad = nullptr;
    uint32_t st_bad = hs_verified_channel_acquire(a, &bad);
    check(st_bad == HS_STATUS_HANDSHAKE || st_bad == HS_STATUS_STATE,
          "wrong expected cert denied");
    check(bad == nullptr, "no handle for wrong expected cert");
    check_status(
        hs_peer_expected_cert_set(a, reinterpret_cast<const char*>(cert_b),
                                  cert_b_len),
        HS_STATUS_OK, "A restore correct expected cert");
    hs_verified_channel* va2 = nullptr;
    check_status(hs_verified_channel_acquire(a, &va2), HS_STATUS_OK,
                 "A reacquire after restore");
    check(va2 != nullptr && va2 != va, "replacement handle distinct");
    check_status(hs_verified_channel_binding_export(
                     va, binding_a, sizeof binding_a, &binding_a_len),
                 HS_STATUS_STATE, "relay old binding denied after repin");
    uint32_t valid = 1;
    check_status(hs_verified_channel_valid(va, &valid), HS_STATUS_OK,
                 "old handle query");
    check(valid == 0, "old handle invalidated on replacement");
    if (va2) hs_verified_channel_release(va2);
    if (vb) hs_verified_channel_release(vb);
    if (va) hs_verified_channel_release(va);
  }

  // Selected transport evidence from native stats (not offer/answer alone).
  // Require BOTH local AND remote selected candidates to be type relay, and
  // relay_protocol/url evidence for TURN TLS/TCP on BOTH peers independently.
  char json[HS_MAX_SELECTED_JSON_BYTES];
  size_t jlen = 0;
  check_status(hs_peer_selected_transport_export(a, json, sizeof json, &jlen),
               HS_STATUS_OK, "selected transport export A");
  std::string sa(json, jlen);
  // Split local/remote objects so one substring cannot satisfy both peers.
  auto extract_obj = [](const std::string& s, const char* key) -> std::string {
    auto pos = s.find(std::string("\"") + key + "\":");
    if (pos == std::string::npos) return {};
    pos = s.find('{', pos);
    if (pos == std::string::npos) return {};
    int depth = 0;
    for (size_t i = pos; i < s.size(); ++i) {
      if (s[i] == '{') depth++;
      else if (s[i] == '}') {
        depth--;
        if (depth == 0) return s.substr(pos, i - pos + 1);
      }
    }
    return {};
  };
  std::string a_local = extract_obj(sa, "local");
  std::string a_remote = extract_obj(sa, "remote");
  check(a_local.find("\"type\":\"relay\"") != std::string::npos,
        "A local selected type relay");
  check(a_remote.find("\"type\":\"relay\"") != std::string::npos,
        "A remote selected type relay");
  // TLS/TCP carrier evidence is on LOCAL selected candidate only. Remote
  // stats may omit relay_protocol/url; do not fabricate or require them.
  check(a_local.find("\"relay_protocol\":\"tls\"") != std::string::npos ||
            a_local.find("\"url\":\"turns:") != std::string::npos,
        "A local TURN TLS/TCP carrier evidence");
  check(sa.find("\"dtls_state\":\"connected\"") != std::string::npos,
        "negotiated DTLS connected");
  {
    uint32_t calls = 0, accepts = 0, rejects = 0;
    check_status(hs_peer_turn_trust_diagnostics(a, &calls, &accepts, &rejects),
                 HS_STATUS_OK, "A trust diagnostics readable");
    check(calls > 0, "TURN TLS verifier invoked");
    check(accepts > 0, "TURN TLS verifier accepted pin");
  }
  check(sa.find("\"turn_relay_only\":true") != std::string::npos,
        "peer marked relay-only");

  jlen = 0;
  check_status(hs_peer_selected_transport_export(b, json, sizeof json, &jlen),
               HS_STATUS_OK, "selected transport export B");
  std::string sb(json, jlen);
  std::string b_local = extract_obj(sb, "local");
  std::string b_remote = extract_obj(sb, "remote");
  check(b_local.find("\"type\":\"relay\"") != std::string::npos,
        "B local selected type relay");
  check(b_remote.find("\"type\":\"relay\"") != std::string::npos,
        "B remote selected type relay");
  check(b_local.find("\"relay_protocol\":\"tls\"") != std::string::npos ||
            b_local.find("\"url\":\"turns:") != std::string::npos,
        "B local TURN TLS/TCP carrier evidence");
  {
    uint32_t calls = 0, accepts = 0, rejects = 0;
    check_status(hs_peer_turn_trust_diagnostics(b, &calls, &accepts, &rejects),
                 HS_STATUS_OK, "B trust diagnostics readable");
    check(calls > 0, "B TURN TLS verifier invoked");
    check(accepts > 0, "B TURN TLS verifier accepted pin");
  }

  std::printf("selected_a=%s\n", sa.c_str());
  std::printf("selected_b=%s\n", sb.c_str());

  hs_peer_close(a);
  hs_peer_close(b);
  hs_peer_drain(a, 3000);
  hs_peer_drain(b, 3000);
  return failures == 0 ? 0 : 1;
}

static int run_negative(hs_engine* eng, const std::map<std::string, std::string>& kv,
                        const char* scenario) {
  std::printf("scenario %s (must fail closed, no direct fallback)\n", scenario);
  TurnCfg cfg = build_cfg(kv);
  if (std::strcmp(scenario, "wrong-cred") == 0) {
    cfg.pass = "definitely-wrong-password";
    cfg.raw.password = cfg.pass.c_str();
    cfg.raw.password_len = static_cast<uint32_t>(cfg.pass.size());
  }
  if (std::strcmp(scenario, "wrong-host") == 0) {
    // Host provided by the lab runner: a real loopback name that reaches the
    // healthy server but mismatches the cert SAN. Not a DNS failure.
    // (Lab writes host=localhost with cert SAN=IP:127.0.0.1 only.)
  }
  if (std::strcmp(scenario, "no-relay") == 0) {
    cfg.raw.port = 1;  // nothing listens; no silent fallback allowed
  }

  hs_peer* a = nullptr;
  hs_peer* b = nullptr;
  uint32_t st = hs_peer_create_relay(eng, &cfg.raw, &a);
  if (st == HS_STATUS_UNAVAILABLE) {
    check(0, "exclusive pin build mode (create_relay available)");
    return 1;
  }
  // Peer objects may construct; the connection must then fail.
  check_status(st, HS_STATUS_OK, "peer A created for negative");
  if (st != HS_STATUS_OK) return 1;
  st = hs_peer_create_relay(eng, &cfg.raw, &b);
  check_status(st, HS_STATUS_OK, "peer B created for negative");
  if (st != HS_STATUS_OK) return 1;

  check_status(hs_channel_create(a, HS_PRODUCT_CHANNEL_LABEL,
                                 std::strlen(HS_PRODUCT_CHANNEL_LABEL)),
               HS_STATUS_OK, "channel A (initiator only)");
  check(negotiate(a, b), "offer/answer (config only)");
  check(exchange_ice(a, b, 15000),
        "negative relay ICE gathering completed");

  PeerCtx ca{a}, cb{b};
  // Short deadline: these must not open.
  bool a_open = wait_until(channel_open_pred, &ca, 8000);
  bool b_open = wait_until(channel_open_pred, &cb, 8000);
  check(!a_open, "peer A must not open (no silent fallback)");
  check(!b_open, "peer B must not open (no silent fallback)");

  char json[HS_MAX_SELECTED_JSON_BYTES];
  size_t jlen = 0;
  uint32_t est = hs_peer_selected_transport_export(a, json, sizeof json, &jlen);
  std::string s;
  if (est == HS_STATUS_OK) {
    s.assign(json, jlen);
    // If stats appear, they must not show a working relay selection.
    check(s.find("\"dtls_state\":\"connected\"") == std::string::npos,
          "no connected DTLS on negative");
  } else {
    check(1, "no selected transport on negative");
  }

  // Causal TLS-negative evidence from REAL verifier callbacks, independent
  // of selected-route existence. Setup/unavailable/timeout/DNS must not count
  // as genuine TLS rejection and must fail the negative gate when TLS was
  // expected to be reached.
  uint32_t vcalls = 0, vacc = 0, vrej = 0;
  uint32_t vst = hs_peer_turn_trust_diagnostics(a, &vcalls, &vacc, &vrej);
  check_status(vst, HS_STATUS_OK, "negative trust diagnostics readable");
  std::printf("trust_diag calls=%u accepts=%u rejects=%u\n", vcalls, vacc, vrej);
  if (std::strcmp(scenario, "wrong-cert") == 0) {
    // Wrong pin against a healthy loopback TLS listener. Verifier must run
    // and deny. calls==0 would be setup/DNS failure, not cert reject.
    check(vcalls > 0, "wrong-cert: custom verifier actually invoked");
    check(vrej > 0 && vacc == 0, "wrong-cert: verifier rejected pin (no accept)");
    check(!a_open && !b_open, "wrong-cert: TLS rejected after verifier deny");
  }
  if (std::strcmp(scenario, "wrong-host") == 0) {
    // host=127.0.0.1 reaches the healthy v4 loopback TLS listener with the
    // correct pin. Cert SAN=DNS:localhost only, so SSLPostConnectionCheck
    // (X509_check_host, always on) rejects the name. Pin must ACCEPT;
    // calls==0 is a setup/DNS failure and must not pass as hostname reject.
    check(vcalls > 0, "wrong-host: TLS verifier reached (not setup/DNS fail)");
    check(vacc > 0 && vrej == 0, "wrong-host: real pin accepted (hostname is the reject)");
    check(!a_open && !b_open, "wrong-host: hostname check rejected");
  }
  if (std::strcmp(scenario, "wrong-cred") == 0) {
    // Valid-in-time REST credential with wrong password. TLS must accept the
    // real pin; allocate then refuses. calls==0 is setup failure, not auth.
    check(vcalls > 0, "wrong-cred: TLS verifier reached (not setup fail)");
    check(vacc > 0 && vrej == 0, "wrong-cred: real pin accepted (auth is the reject)");
    check(!a_open && !b_open, "wrong-cred: allocate refused");
  }
  if (std::strcmp(scenario, "no-relay") == 0) {
    // Unreachable TURN: must not open. Independent diagnostics: this is NOT
    // a TLS rejection (typically calls==0 because TLS never completes).
    check(!a_open && !b_open, "no-relay: unreachable refused");
    check(!(vcalls > 0 && vrej > 0 && vacc == 0),
          "no-relay: not reported as TLS pin reject");
  }
  hs_peer_close(a);
  hs_peer_close(b);
  hs_peer_drain(a, 3000);
  hs_peer_drain(b, 3000);
  return failures == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <scenario> [config-file]\n", argv[0]);
    return 2;
  }
  const std::string scenario = argv[1];
  std::printf("hs_webrtc_relay_harness %s abi=%u scenario=%s\n",
              hs_engine_version(), hs_abi_version(), scenario.c_str());

  hs_engine* eng = nullptr;
  check_status(hs_engine_init(&eng), HS_STATUS_OK, "engine init");
  if (!eng) return 1;

  int rc = 1;
  if (scenario == "validate") {
    rc = run_validate(eng);
  } else {
    if (argc < 3) {
      std::fprintf(stderr, "config file required for scenario %s\n",
                   scenario.c_str());
      hs_engine_shutdown(eng);
      return 2;
    }
    auto kv = read_config(argv[2]);
    if (kv.empty()) {
      std::fprintf(stderr, "empty/unreadable config\n");
      hs_engine_shutdown(eng);
      return 2;
    }
    if (scenario == "positive") {
      rc = run_positive(eng, kv);
    } else if (scenario == "wrong-cert" || scenario == "wrong-cred" ||
               scenario == "no-relay" || scenario == "wrong-host") {
      rc = run_negative(eng, kv, scenario.c_str());
    } else {
      std::fprintf(stderr, "unknown scenario %s\n", scenario.c_str());
      rc = 2;
    }
  }

  hs_engine_shutdown(eng);
  std::printf("\n%d checks, %d failures\n", checks, failures);
  std::printf("relay_harness_exit=%d\n", rc);
  return rc;
}
