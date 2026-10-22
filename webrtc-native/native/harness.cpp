// harness.cpp -- E01 native two-peer WebRTC connection proof (ABI-3 subset).
//
// Establishes two real PeerConnections with generated real DTLS certificates,
// performs offer/answer and ICE exchange, opens a product data channel in both
// directions, exchanges bounded messages, extracts the actual negotiated peer
// certificate from the connected DTLS transport, proves tampered-expected-
// certificate denial, proves handle invalidation on close/replacement, and
// exercises invalid handles, two engines, free/release churn and drain.
//
// The video checks below exercise the native bounded media primitives with a
// synthetic source and host-verified test authority. They do not prove the
// product grant protocol, physical-console capture, or endpoint integration.

#include "hs_webrtc.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <cstdio>
#include <cstring>
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

// Test-only seam from the harness static bridge (HS_TEST_DRAIN_FAULT).
// Not part of the published ABI; shared library builds omit this symbol.
extern "C" void hs_test_force_drain_timeout(int on);

static bool wait_until(std::function<bool()> pred, int timeout_ms) {
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return pred();
}

// Exchange local ICE both ways until both sides stop producing or timeout.
static void exchange_ice(hs_peer* a, hs_peer* b, int rounds) {
  char buf[HS_MAX_SDP_BYTES];
  size_t len = 0;
  for (int i = 0; i < rounds; i++) {
    bool moved = false;
    while (hs_peer_poll_ice(a, buf, sizeof buf, &len) == HS_STATUS_OK) {
      hs_peer_add_ice(b, buf, len);
      moved = true;
    }
    while (hs_peer_poll_ice(b, buf, sizeof buf, &len) == HS_STATUS_OK) {
      hs_peer_add_ice(a, buf, len);
      moved = true;
    }
    if (!moved) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
}

static bool channel_open(hs_peer* p) {
  uint32_t st = 0;
  if (hs_peer_state(p, &st) != HS_STATUS_OK) return false;
  return st == HS_PEER_STATE_CHANNEL_OPEN || st == HS_PEER_STATE_CONNECTED;
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  std::printf("hs_webrtc_harness %s abi=%u\n", hs_engine_version(),
              hs_abi_version());
  check(hs_abi_version() == HS_ABI_VERSION, "abi version is 3");

  uint32_t caps = 0;
  check_status(hs_engine_capabilities(&caps), HS_STATUS_OK, "capabilities");
  check((caps & HS_CAP_INITIALIZATION) != 0, "cap initialization");
  check((caps & HS_CAP_NEGOTIATION) != 0, "cap negotiation");
  check((caps & HS_CAP_CHANNEL_EVIDENCE) != 0, "cap channel evidence");
  check((caps & HS_CAP_DRAIN) != 0, "cap drain");
  check((caps & HS_CAP_CAPTURE) == 0, "cap capture unavailable");
  check((caps & HS_CAP_ADMISSION) == 0, "cap admission unavailable");
  check((caps & HS_CAP_MEDIA) == 0, "cap media unavailable");

  // The APIs are implemented primitives, but their capability bits remain
  // off until the application capture and authority integrations pass.
  check_status(hs_capture_begin(nullptr, 0), HS_STATUS_NULL,
               "capture rejects null peer");
  check_status(hs_admission_begin(nullptr, nullptr, 0, 0), HS_STATUS_NULL,
               "admission rejects null peer");
  check_status(hs_media_frame_acquire(nullptr, 0, nullptr, nullptr, nullptr),
               HS_STATUS_NULL, "media rejects null peer");

  hs_engine* eng = nullptr;
  check_status(hs_engine_init(&eng), HS_STATUS_OK, "engine init");
  check(eng != nullptr, "engine handle non-null");

  // Two live engines must not share token authority.
  hs_engine* eng2 = nullptr;
  check_status(hs_engine_init(&eng2), HS_STATUS_OK, "second engine init");
  check(eng2 != nullptr && eng2 != eng, "second engine distinct handle");

  hs_peer* a = nullptr;
  hs_peer* b = nullptr;
  check_status(hs_peer_create(eng, &a), HS_STATUS_OK, "peer A create");
  check_status(hs_peer_create(eng, &b), HS_STATUS_OK, "peer B create");
  check(a != nullptr && b != nullptr && a != b, "peer handles distinct");

  uint32_t gen_a = 0, gen_b = 0;
  hs_peer_generation(a, &gen_a);
  hs_peer_generation(b, &gen_b);
  check(gen_a != 0 && gen_b != 0 && gen_a != gen_b, "peer generations distinct");

  check_status(hs_peer_video_prepare(a, HS_VIDEO_ROLE_SEND_ONLY), HS_STATUS_OK,
               "prepare A as send-only before negotiation");
  check_status(hs_peer_video_prepare(b, HS_VIDEO_ROLE_RECEIVE_ONLY), HS_STATUS_OK,
               "prepare B as receive-only before negotiation");
  check_status(hs_peer_video_prepare(a, 0), HS_STATUS_INVALID,
               "reject an invalid video role");

  // Real DTLS certificates (generated by the engine).
  uint8_t cert_a[HS_MAX_CERT_PEM_BYTES];
  uint8_t cert_b[HS_MAX_CERT_PEM_BYTES];
  uint32_t cert_a_len = 0, cert_b_len = 0;
  check_status(hs_peer_local_cert_export(a, cert_a, sizeof cert_a, &cert_a_len),
               HS_STATUS_OK, "peer A local cert exported");
  check_status(hs_peer_local_cert_export(b, cert_b, sizeof cert_b, &cert_b_len),
               HS_STATUS_OK, "peer B local cert exported");
  check(cert_a_len > 0 && cert_b_len > 0, "local certs non-empty");
  check(std::memcmp(cert_a, cert_b, cert_a_len < cert_b_len ? cert_a_len
                                                           : cert_b_len) != 0 ||
            cert_a_len != cert_b_len,
        "local certs differ");

  // Product data channel before offer so SDP carries it.
  check_status(hs_channel_create(a, HS_PRODUCT_CHANNEL_LABEL,
                                 std::strlen(HS_PRODUCT_CHANNEL_LABEL)),
               HS_STATUS_OK, "channel create on A");

  // Offer / answer.
  char offer[HS_MAX_SDP_BYTES];
  size_t offer_len = 0;
  check_status(hs_peer_create_offer(a, offer, sizeof offer, &offer_len),
               HS_STATUS_OK, "create offer");
  check(offer_len > 0, "offer non-empty");

  check_status(hs_peer_set_remote(b, "offer", 5, offer, offer_len),
               HS_STATUS_OK, "B set remote offer");

  char answer[HS_MAX_SDP_BYTES];
  size_t answer_len = 0;
  check_status(hs_peer_create_answer(b, answer, sizeof answer, &answer_len),
               HS_STATUS_OK, "create answer");
  check(answer_len > 0, "answer non-empty");

  check_status(hs_peer_set_remote(a, "answer", 6, answer, answer_len),
               HS_STATUS_OK, "A set remote answer");

  // ICE exchange.
  exchange_ice(a, b, 40);

  // Wait for both endpoints to reach channel open (actual delivery path).
  bool a_open = wait_until([&] { return channel_open(a); }, 15000);
  bool b_open = wait_until([&] { return channel_open(b); }, 15000);
  check(a_open, "peer A channel/connected");
  check(b_open, "peer B channel/connected");

  // An open DTLS channel is not yet an identity-verified product channel.
  const char* early_msg = "hs-product-before-pin";
  uint8_t rbuf[HS_MAX_MSG_BYTES];
  uint32_t rlen = 0;
  check_status(hs_channel_send(a, reinterpret_cast<const uint8_t*>(early_msg),
                               static_cast<uint32_t>(std::strlen(early_msg))),
               HS_STATUS_HANDSHAKE, "unverified send denied");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_HANDSHAKE, "unverified receive denied");

  // Channel evidence: expected cert = other side's real local cert.
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

  // A locally verified sender cannot make the unverified receiver expose
  // early channel data later, after the receiver installs its pin.
  check_status(hs_verified_channel_acquire(a, &va), HS_STATUS_OK,
               "A preflight verified-channel acquire");
  check_status(hs_channel_send(a, reinterpret_cast<const uint8_t*>(early_msg),
                               static_cast<uint32_t>(std::strlen(early_msg))),
               HS_STATUS_OK, "verified A sends to unverified B");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_HANDSHAKE, "B does not expose pre-pin data");
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  check_status(hs_verified_channel_acquire(b, &vb), HS_STATUS_OK,
               "B verified-channel acquire after early data");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_EXHAUSTED, "pre-pin data was dropped");

  // Tampered expected certificate must be denied (before good acquire).
  {
    hs_peer* tmp_p = nullptr;
    check_status(hs_peer_create(eng, &tmp_p), HS_STATUS_OK, "tamper peer create");
    // Use A with a wrong expected cert first.
    std::string tampered = std::string(reinterpret_cast<char*>(cert_a), cert_a_len);
    // Flip a character inside the PEM body (not header) to force mismatch.
    if (tampered.size() > 40) {
      tampered[40] = (tampered[40] == 'A') ? 'B' : 'A';
    }
    check_status(hs_peer_expected_cert_set(a, tampered.c_str(), tampered.size()),
                 HS_STATUS_OK, "A set tampered expected cert");
    hs_verified_channel* bad = nullptr;
    uint32_t st = hs_verified_channel_acquire(a, &bad);
    check(st == HS_STATUS_HANDSHAKE || st == HS_STATUS_STATE,
          "tampered expected cert denied");
    check(bad == nullptr, "no handle issued for tampered cert");
    check_status(hs_channel_send(a, reinterpret_cast<const uint8_t*>(early_msg),
                                 static_cast<uint32_t>(std::strlen(early_msg))),
                 HS_STATUS_HANDSHAKE, "send denied after pin replacement");
    check_status(hs_channel_poll(a, rbuf, sizeof rbuf, &rlen),
                 HS_STATUS_HANDSHAKE, "receive denied after pin replacement");

    // Restore correct expected cert.
    check_status(
        hs_peer_expected_cert_set(a, reinterpret_cast<const char*>(cert_b),
                                  cert_b_len),
        HS_STATUS_OK, "A restore correct expected cert");
    check_status(hs_verified_channel_release(va), HS_STATUS_OK,
                 "release A preflight handle after pin replacement");
    va = nullptr;

    if (tmp_p) {
      hs_peer_close(tmp_p);
      uint32_t fr = hs_peer_free(tmp_p);
      check(fr == HS_STATUS_OK || fr == HS_STATUS_TIMEOUT,
            "tamper helper peer free");
    }
  }

  // Restore A's verified binding after the tampered-pin check; B's binding
  // remains the one acquired above.
  check_status(hs_verified_channel_acquire(a, &va), HS_STATUS_OK,
               "A verified-channel acquire");
  check(va != nullptr, "A handle issued");
  check(vb != nullptr, "B handle issued");

  uint8_t binding_a[HS_MAX_CHANNEL_BINDING_BYTES];
  uint8_t binding_b[HS_MAX_CHANNEL_BINDING_BYTES];
  uint32_t binding_a_len = 0;
  uint32_t binding_b_len = 0;
  check_status(hs_verified_channel_binding_export(
                   va, binding_a, sizeof binding_a, &binding_a_len),
               HS_STATUS_OK, "A exports its DTLS/SCTP channel binding");
  check_status(hs_verified_channel_binding_export(
                   vb, binding_b, sizeof binding_b, &binding_b_len),
               HS_STATUS_OK, "B exports its DTLS/SCTP channel binding");
  check(binding_a_len > 0 && binding_a_len == binding_b_len &&
            std::memcmp(binding_a, binding_b, binding_a_len) == 0,
        "both peers derive the same exact product-channel binding");

  // A native lease is not a grant protocol: this harness supplies an
  // independently verified authority decision and checks that the bridge
  // fences the media APIs to this exact channel binding and peer generation.
  check_status(hs_capture_begin(a, gen_a), HS_STATUS_HANDSHAKE,
               "capture denied before observation admission");
  constexpr uint32_t frame_width = 64;
  constexpr uint32_t frame_height = 64;
  constexpr uint32_t frame_stride = frame_width * 4;
  std::vector<uint8_t> screen_frame(frame_stride * frame_height, 0);
  for (uint32_t y = 0; y < frame_height; ++y) {
    for (uint32_t x = 0; x < frame_width; ++x) {
      const size_t offset = static_cast<size_t>(y) * frame_stride + x * 4U;
      screen_frame[offset] = static_cast<uint8_t>((x * 3U) & 0xffU);
      screen_frame[offset + 1] = static_cast<uint8_t>((y * 5U) & 0xffU);
      screen_frame[offset + 2] = 220;
      screen_frame[offset + 3] = 255;
    }
  }
  std::vector<uint8_t> received_frame(HS_MAX_SCREEN_FRAME_BYTES, 0);
  uint32_t received_width = 0;
  uint32_t received_height = 0;
  check_status(hs_admission_begin(a, binding_a, binding_a_len, 5000),
               HS_STATUS_OK, "A admits synthetic test authority to its live channel");
  check_status(hs_admission_begin(b, binding_b, binding_b_len, 5000),
               HS_STATUS_OK, "B admits synthetic test authority to its live channel");
  check_status(hs_capture_begin(a, gen_a), HS_STATUS_OK,
               "A starts its admitted video source");
  uint32_t last_push_status = HS_STATUS_INTERNAL;
  uint32_t last_frame_status = HS_STATUS_INTERNAL;
  const bool received_video = wait_until(
      [&] {
        last_push_status = hs_peer_video_frame_push(
            a, screen_frame.data(), frame_stride * frame_height,
            frame_width, frame_height, frame_stride);
        last_frame_status = hs_media_frame_acquire(
            b, static_cast<uint32_t>(received_frame.size()), received_frame.data(),
            &received_width, &received_height);
        return last_frame_status == HS_STATUS_OK;
      },
      15000);
  check(received_video, "B receives a real decoded WebRTC video frame");
  check(last_push_status == HS_STATUS_OK,
        "A pushes bounded BGRA frames through the admitted source");
  check(received_width == frame_width && received_height == frame_height,
        "B frame mailbox reports the decoded dimensions");
  const size_t received_frame_bytes =
      static_cast<size_t>(received_width) * received_height * 4U;
  check(received_frame_bytes <= received_frame.size() &&
            std::any_of(received_frame.begin(),
                        received_frame.begin() + static_cast<std::ptrdiff_t>(received_frame_bytes),
                        [](uint8_t value) { return value != 0; }),
        "B mailbox contains decoded BGRA pixels");

  std::array<uint8_t, HS_MAX_CHANNEL_BINDING_BYTES> wrong_binding{};
  std::memcpy(wrong_binding.data(), binding_a, binding_a_len);
  wrong_binding[0] ^= 1U;
  check_status(hs_admission_begin(a, wrong_binding.data(), binding_a_len, 100),
               HS_STATUS_HANDSHAKE,
               "admission rejects a binding from another channel");
  check_status(hs_capture_end(a), HS_STATUS_OK, "A stops capture");
  check_status(hs_admission_end(a), HS_STATUS_OK, "A revokes the test lease");
  check_status(hs_admission_end(b), HS_STATUS_OK, "B revokes the test lease");
  std::fill(received_frame.begin(), received_frame.end(), uint8_t{0xaa});
  received_width = 1;
  received_height = 1;
  check_status(hs_media_frame_acquire(
                   b, static_cast<uint32_t>(received_frame.size()),
                   received_frame.data(), &received_width, &received_height),
               HS_STATUS_HANDSHAKE, "revoked viewer lease denies frame acquisition");
  check(received_width == 0 && received_height == 0 &&
            std::all_of(received_frame.begin(), received_frame.end(),
                        [](uint8_t value) { return value == 0; }),
        "revocation clears dimensions and the entire output buffer");

  // Expiry is measured with a monotonic clock. Both peers must fail closed and
  // wipe their frame state once the short lease deadline has passed.
  check_status(hs_admission_begin(a, binding_a, binding_a_len, 100),
               HS_STATUS_OK, "A starts a short expiry-test lease");
  check_status(hs_admission_begin(b, binding_b, binding_b_len, 100),
               HS_STATUS_OK, "B starts a short expiry-test lease");
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  std::fill(received_frame.begin(), received_frame.end(), uint8_t{0xaa});
  received_width = 1;
  received_height = 1;
  check_status(hs_media_frame_acquire(
                   b, static_cast<uint32_t>(received_frame.size()),
                   received_frame.data(), &received_width, &received_height),
               HS_STATUS_HANDSHAKE, "expired viewer lease denies frame acquisition");
  check_status(hs_capture_begin(a, gen_a), HS_STATUS_HANDSHAKE,
               "expired sender lease denies capture");
  check(received_width == 0 && received_height == 0 &&
            std::all_of(received_frame.begin(), received_frame.end(),
                        [](uint8_t value) { return value == 0; }),
        "expiry clears dimensions and the entire output buffer");
  check_status(hs_admission_end(a), HS_STATUS_OK, "A clears expired lease");
  check_status(hs_admission_end(b), HS_STATUS_OK, "B clears expired lease");

  // Bounded product messages both directions, now that both peer identities
  // are pinned to the actual negotiated certificates.
  const char* msg_a2b = "hs-product-ping-a2b";
  const char* msg_b2a = "hs-product-pong-b2a";
  check_status(hs_channel_send(a, reinterpret_cast<const uint8_t*>(msg_a2b),
                               static_cast<uint32_t>(std::strlen(msg_a2b))),
               HS_STATUS_OK, "send verified A->B");
  check_status(hs_channel_send(b, reinterpret_cast<const uint8_t*>(msg_b2a),
                               static_cast<uint32_t>(std::strlen(msg_b2a))),
               HS_STATUS_OK, "send verified B->A");
  bool got_b = wait_until(
      [&] {
        rlen = 0;
        return hs_channel_poll(b, rbuf, sizeof rbuf, &rlen) == HS_STATUS_OK &&
               rlen == std::strlen(msg_a2b) &&
               std::memcmp(rbuf, msg_a2b, rlen) == 0;
      },
      10000);
  check(got_b, "B received verified A->B product message");
  bool got_a = wait_until(
      [&] {
        rlen = 0;
        return hs_channel_poll(a, rbuf, sizeof rbuf, &rlen) == HS_STATUS_OK &&
               rlen == std::strlen(msg_b2a) &&
               std::memcmp(rbuf, msg_b2a, rlen) == 0;
      },
      10000);
  check(got_a, "A received verified B->A product message");

  uint8_t exported[HS_MAX_CERT_PEM_BYTES];
  uint32_t elen = 0;
  check_status(hs_verified_channel_export(va, exported, sizeof exported, &elen),
               HS_STATUS_OK, "A export negotiated cert");
  check(elen > 0, "exported cert non-empty");
  // Exported must equal B's local cert (the actual negotiated peer identity).
  check(elen == cert_b_len &&
            std::memcmp(exported, cert_b, elen) == 0,
        "A exported cert equals B local cert");

  uint32_t vgen = 0;
  check_status(hs_verified_channel_generation(va, &vgen), HS_STATUS_OK,
               "A handle generation");
  check(vgen == gen_a, "handle bound to A peer generation");

  uint32_t valid = 0;
  check_status(hs_verified_channel_valid(va, &valid), HS_STATUS_OK,
               "A handle valid query");
  check(valid == 1, "A handle valid after acquire");

  // Replacement invalidates the previous handle.
  const char* queued_before_repin = "hs-product-queued-before-repin";
  check_status(hs_channel_send(
                   b, reinterpret_cast<const uint8_t*>(queued_before_repin),
                   static_cast<uint32_t>(std::strlen(queued_before_repin))),
               HS_STATUS_OK, "queue data before pin replacement");
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  check_status(hs_peer_expected_cert_set(
                   a, reinterpret_cast<const char*>(cert_b), cert_b_len),
               HS_STATUS_OK, "A repin clears queued inbound data");
  check_status(hs_channel_poll(a, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_HANDSHAKE, "receive denied during repin");
  hs_verified_channel* va2 = nullptr;
  check_status(hs_verified_channel_acquire(a, &va2), HS_STATUS_OK,
               "A verified-channel reacquire");
  check(va2 != nullptr && va2 != va, "replacement handle distinct");
  check_status(hs_channel_poll(a, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_EXHAUSTED, "repin discarded previously queued data");
  check_status(hs_verified_channel_valid(va, &valid), HS_STATUS_OK,
               "old handle query after replacement");
  check(valid == 0, "old handle invalidated on replacement");
  elen = 1;
  check_status(hs_verified_channel_export(va, exported, sizeof exported, &elen),
               HS_STATUS_STATE, "old handle export denied after replacement");
  check(elen == 0, "failed certificate export clears output length");
  binding_a_len = 1;
  check_status(hs_verified_channel_binding_export(
                   va, binding_a, sizeof binding_a, &binding_a_len),
               HS_STATUS_STATE, "old channel binding denied after replacement");
  check(binding_a_len == 0, "failed channel binding export clears output length");
  check_status(hs_verified_channel_release(va), HS_STATUS_OK,
               "release old handle");

  // Invalid / foreign / released handles must not fault or grant authority.
  hs_verified_channel* forged =
      reinterpret_cast<hs_verified_channel*>(static_cast<uintptr_t>(0x1234));
  uint32_t fv = 1;
  uint32_t fr = hs_verified_channel_valid(forged, &fv);
  check(fr == HS_STATUS_NULL || fr == HS_STATUS_STATE,
        "forged handle rejected");
  check(fv == 0, "forged handle not valid");
  check(hs_verified_channel_export(forged, exported, sizeof exported, &elen) !=
            HS_STATUS_OK,
        "forged handle export denied");
  // Must not report a successful release of a forged handle.
  check(hs_verified_channel_release(forged) != HS_STATUS_OK,
        "forged handle release safe");

  hs_peer* forged_peer =
      reinterpret_cast<hs_peer*>(static_cast<uintptr_t>(0x5678));
  uint32_t pst = 99;
  check(hs_peer_state(forged_peer, &pst) != HS_STATUS_OK,
        "forged peer state denied");
  check(hs_peer_close(forged_peer) != HS_STATUS_OK,
        "forged peer close denied");
  check(hs_peer_free(forged_peer) != HS_STATUS_OK,
        "forged peer free denied");

  // Two engines: peer on eng2 must not resolve eng1 authority.
  hs_peer* c = nullptr;
  check_status(hs_peer_create(eng2, &c), HS_STATUS_OK, "eng2 peer create");
  check(c != a && c != b, "eng2 peer distinct from eng1 peers");
  hs_verified_channel* vc2 = nullptr;
  // Without a connection this must fail closed (handshake), not succeed.
  uint32_t acq2 = hs_verified_channel_acquire(c, &vc2);
  check(acq2 != HS_STATUS_OK, "eng2 peer acquire fails without DTLS");
  check(vc2 == nullptr, "eng2 peer no handle without DTLS");

  // Free/release churn (boundedness).
  for (int i = 0; i < 32; i++) {
    hs_peer* t = nullptr;
    if (hs_peer_create(eng2, &t) != HS_STATUS_OK) {
      check(0, "churn peer create");
      break;
    }
    hs_peer_close(t);
    uint32_t r = hs_peer_free(t);
    if (r != HS_STATUS_OK && r != HS_STATUS_TIMEOUT) {
      check(0, "churn peer free");
      break;
    }
  }
  check(1, "32x peer free/release churn completed");

  check_status(hs_verified_channel_release(vb), HS_STATUS_OK,
               "release current verified binding");
  check_status(hs_channel_send(b, reinterpret_cast<const uint8_t*>(early_msg),
                               static_cast<uint32_t>(std::strlen(early_msg))),
               HS_STATUS_HANDSHAKE, "send denied after handle release");
  check_status(hs_channel_poll(b, rbuf, sizeof rbuf, &rlen),
               HS_STATUS_HANDSHAKE, "receive denied after handle release");
  vb = nullptr;

  // Close invalidates handles.
  check_status(hs_peer_close(a), HS_STATUS_OK, "close peer A");
  check_status(hs_verified_channel_valid(va2, &valid), HS_STATUS_OK,
               "handle query after owner close");
  check(valid == 0, "handle invalidated on close");
  hs_verified_channel* after_close = nullptr;
  check_status(hs_verified_channel_acquire(a, &after_close), HS_STATUS_STATE,
               "verified-channel acquire denied after peer close");
  check(after_close == nullptr, "closed peer receives no verified handle");
  char ice_after_close[1];
  size_t ice_after_close_len = 0;
  check_status(hs_peer_poll_ice(a, ice_after_close, sizeof ice_after_close,
                                &ice_after_close_len),
               HS_STATUS_STATE, "ICE poll denied after peer close");

  // Drain reports honestly. A successful retiring drain removes the registry
  // entry (lab semantics: not a two-phase free). A timed-out drain retains
  // the peer; one subsequent free then returns OK or TIMEOUT.
  uint32_t d1 = hs_peer_drain(a, 2000);
  check(d1 == HS_STATUS_OK || d1 == HS_STATUS_TIMEOUT, "drain A");
  uint32_t d2 = hs_peer_drain(b, 2000);
  check(d2 == HS_STATUS_OK || d2 == HS_STATUS_TIMEOUT, "drain B");

  // Free after drain — exactly once, conditional on the drain outcome.
  {
    uint32_t fa = hs_peer_free(a);
    if (d1 == HS_STATUS_OK) {
      check(fa == HS_STATUS_NULL, "free A after retiring drain is NULL");
    } else {
      check(fa == HS_STATUS_OK || fa == HS_STATUS_TIMEOUT,
            "free A after timed-out drain");
    }
    uint32_t fb = hs_peer_free(b);
    if (d2 == HS_STATUS_OK) {
      check(fb == HS_STATUS_NULL, "free B after retiring drain is NULL");
    } else {
      check(fb == HS_STATUS_OK || fb == HS_STATUS_TIMEOUT,
            "free B after timed-out drain");
    }
  }
  if (c) {
    hs_peer_close(c);
    hs_peer_free(c);
  }

  // Release remaining handles.
  hs_verified_channel_release(va2);

  // Engine drain/shutdown.
  uint32_t ed = hs_engine_drain(eng, 3000);
  check(ed == HS_STATUS_OK || ed == HS_STATUS_TIMEOUT, "engine A drain");
  uint32_t sd1 = hs_engine_shutdown(eng);
  check(sd1 == HS_STATUS_OK || sd1 == HS_STATUS_TIMEOUT, "engine A shutdown");
  uint32_t sd2 = hs_engine_shutdown(eng2);
  check(sd2 == HS_STATUS_OK || sd2 == HS_STATUS_TIMEOUT, "engine B shutdown");

  // After shutdown, handles must not resolve.
  check(hs_peer_state(a, &pst) != HS_STATUS_OK, "peer A gone after shutdown");
  check(hs_verified_channel_valid(vb, &fv) != HS_STATUS_OK || fv == 0,
        "handle dead after shutdown");

  // --- slow callback / timeout-then-late-callback / close-free-with-callback ---
  {
    hs_engine* e3 = nullptr;
    check_status(hs_engine_init(&e3), HS_STATUS_OK, "slow-callback engine init");
    hs_peer* s1 = nullptr;
    hs_peer* s2 = nullptr;
    check_status(hs_peer_create(e3, &s1), HS_STATUS_OK, "slow peer1 create");
    check_status(hs_peer_create(e3, &s2), HS_STATUS_OK, "slow peer2 create");
    check_status(hs_channel_create(s1, HS_PRODUCT_CHANNEL_LABEL,
                                   std::strlen(HS_PRODUCT_CHANNEL_LABEL)),
                 HS_STATUS_OK, "slow channel create");

    char off[HS_MAX_SDP_BYTES];
    size_t off_len = 0;
    check_status(hs_peer_create_offer(s1, off, sizeof off, &off_len),
                 HS_STATUS_OK, "slow offer");
    check_status(hs_peer_set_remote(s2, "offer", 5, off, off_len),
                 HS_STATUS_OK, "slow set remote offer");
    char ans[HS_MAX_SDP_BYTES];
    size_t ans_len = 0;
    check_status(hs_peer_create_answer(s2, ans, sizeof ans, &ans_len),
                 HS_STATUS_OK, "slow answer");
    check_status(hs_peer_set_remote(s1, "answer", 6, ans, ans_len),
                 HS_STATUS_OK, "slow set remote answer");
    exchange_ice(s1, s2, 30);

    bool s_open = wait_until([&] { return channel_open(s1) && channel_open(s2); },
                             15000);
    check(s_open, "slow peers connected");

    uint8_t s1_cert[HS_MAX_CERT_PEM_BYTES];
    uint8_t s2_cert[HS_MAX_CERT_PEM_BYTES];
    uint32_t s1_cert_len = 0, s2_cert_len = 0;
    check_status(hs_peer_local_cert_export(s1, s1_cert, sizeof s1_cert,
                                           &s1_cert_len),
                 HS_STATUS_OK, "slow peer1 cert export");
    check_status(hs_peer_local_cert_export(s2, s2_cert, sizeof s2_cert,
                                           &s2_cert_len),
                 HS_STATUS_OK, "slow peer2 cert export");
    check_status(hs_peer_expected_cert_set(
                     s1, reinterpret_cast<const char*>(s2_cert), s2_cert_len),
                 HS_STATUS_OK, "slow peer1 pin peer2");
    check_status(hs_peer_expected_cert_set(
                     s2, reinterpret_cast<const char*>(s1_cert), s1_cert_len),
                 HS_STATUS_OK, "slow peer2 pin peer1");
    hs_verified_channel* sv1 = nullptr;
    hs_verified_channel* sv2 = nullptr;
    check_status(hs_verified_channel_acquire(s1, &sv1), HS_STATUS_OK,
                 "slow peer1 verified channel");
    check_status(hs_verified_channel_acquire(s2, &sv2), HS_STATUS_OK,
                 "slow peer2 verified channel");

    // Flood messages to keep callbacks in flight while we close/drain.
    const char burst[] = "hs-product-burst-payload";
    for (int i = 0; i < 64; i++) {
      hs_channel_send(s1, reinterpret_cast<const uint8_t*>(burst),
                      static_cast<uint32_t>(std::strlen(burst)));
    }
    // Drain with a tiny timeout on a busy peer: must report OK or TIMEOUT
    // honestly, never a silent success while callbacks are live.
    uint32_t dr = hs_peer_drain(s1, 1);
    check(dr == HS_STATUS_OK || dr == HS_STATUS_TIMEOUT,
          "tiny-timeout drain reports honestly");
    // Close/free while callbacks may still be delivering.
    check_status(hs_peer_close(s2), HS_STATUS_OK, "close during in-flight");
    uint32_t fr2 = hs_peer_free(s2);
    check(fr2 == HS_STATUS_OK || fr2 == HS_STATUS_TIMEOUT,
          "free during in-flight is safe");
    // Late completion: a second drain after the storm must still be safe.
    // NULL/STATE are honest if the peer was already retired by the first drain
    // (registry lookup fails closed; never a fabricated success).
    uint32_t dr2 = hs_peer_drain(s1, 2000);
    check(dr2 == HS_STATUS_OK || dr2 == HS_STATUS_TIMEOUT ||
              dr2 == HS_STATUS_STATE || dr2 == HS_STATUS_NULL,
          "post-storm drain safe");
    hs_peer_free(s1);
    // Engine drain must quiesce and dispose any retained peers.
    uint32_t ed = hs_engine_drain(e3, 3000);
    check(ed == HS_STATUS_OK || ed == HS_STATUS_TIMEOUT, "slow engine drain");
    uint32_t sd = hs_engine_shutdown(e3);
    check(sd == HS_STATUS_OK || sd == HS_STATUS_TIMEOUT, "slow engine shutdown");
  }

  // Surviving-engine connection after the first engine is destroyed.
  // If WSACleanup/SSL release of engine A invalidates engine B, real ICE and
  // product messages on B must fail. Object creation alone is not enough.
  {
    hs_engine* eng_a = nullptr;
    hs_engine* eng_b = nullptr;
    check_status(hs_engine_init(&eng_a), HS_STATUS_OK, "survive engine A init");
    check_status(hs_engine_init(&eng_b), HS_STATUS_OK, "survive engine B init");
    uint32_t sa = hs_engine_shutdown(eng_a);
    check(sa == HS_STATUS_OK || sa == HS_STATUS_TIMEOUT, "survive engine A shutdown");
    check(hs_engine_shutdown(eng_a) == HS_STATUS_NULL, "survive double-shutdown A null");

    hs_peer* p1 = nullptr;
    hs_peer* p2 = nullptr;
    check_status(hs_peer_create(eng_b, &p1), HS_STATUS_OK, "survive peer1 create");
    check_status(hs_peer_create(eng_b, &p2), HS_STATUS_OK, "survive peer2 create");
    check_status(hs_channel_create(p1, HS_PRODUCT_CHANNEL_LABEL,
                                   std::strlen(HS_PRODUCT_CHANNEL_LABEL)),
                 HS_STATUS_OK, "survive channel create");

    char off[HS_MAX_SDP_BYTES];
    size_t off_len = 0;
    check_status(hs_peer_create_offer(p1, off, sizeof off, &off_len),
                 HS_STATUS_OK, "survive offer");
    check_status(hs_peer_set_remote(p2, "offer", 5, off, off_len),
                 HS_STATUS_OK, "survive set remote offer");
    char ans[HS_MAX_SDP_BYTES];
    size_t ans_len = 0;
    check_status(hs_peer_create_answer(p2, ans, sizeof ans, &ans_len),
                 HS_STATUS_OK, "survive answer");
    check_status(hs_peer_set_remote(p1, "answer", 6, ans, ans_len),
                 HS_STATUS_OK, "survive set remote answer");
    exchange_ice(p1, p2, 40);

    bool c1 = wait_until([&] { return channel_open(p1); }, 15000);
    bool c2 = wait_until([&] { return channel_open(p2); }, 15000);
    check(c1, "survive peer1 channel/connected");
    check(c2, "survive peer2 channel/connected");

    uint8_t p1_cert[HS_MAX_CERT_PEM_BYTES];
    uint8_t p2_cert[HS_MAX_CERT_PEM_BYTES];
    uint32_t p1_cert_len = 0, p2_cert_len = 0;
    check_status(hs_peer_local_cert_export(p1, p1_cert, sizeof p1_cert,
                                           &p1_cert_len),
                 HS_STATUS_OK, "survive peer1 cert export");
    check_status(hs_peer_local_cert_export(p2, p2_cert, sizeof p2_cert,
                                           &p2_cert_len),
                 HS_STATUS_OK, "survive peer2 cert export");
    check_status(hs_peer_expected_cert_set(
                     p1, reinterpret_cast<const char*>(p2_cert), p2_cert_len),
                 HS_STATUS_OK, "survive peer1 pin peer2");
    check_status(hs_peer_expected_cert_set(
                     p2, reinterpret_cast<const char*>(p1_cert), p1_cert_len),
                 HS_STATUS_OK, "survive peer2 pin peer1");
    hs_verified_channel* pv1 = nullptr;
    hs_verified_channel* pv2 = nullptr;
    check_status(hs_verified_channel_acquire(p1, &pv1), HS_STATUS_OK,
                 "survive peer1 verified channel");
    check_status(hs_verified_channel_acquire(p2, &pv2), HS_STATUS_OK,
                 "survive peer2 verified channel");

    const char* msg = "hs-product-survive-engine-b";
    check_status(hs_channel_send(p1, reinterpret_cast<const uint8_t*>(msg),
                                 static_cast<uint32_t>(std::strlen(msg))),
                 HS_STATUS_OK, "survive send p1->p2");
    bool got = wait_until(
        [&] {
          uint8_t buf[HS_MAX_MSG_BYTES];
          uint32_t n = 0;
          return hs_channel_poll(p2, buf, sizeof buf, &n) == HS_STATUS_OK &&
                 n == std::strlen(msg) &&
                 std::memcmp(buf, msg, n) == 0;
        },
        10000);
    check(got, "survive p2 received product message");

    check_status(hs_channel_close(p1), HS_STATUS_OK, "survive channel close");
    uint32_t channel_valid = 1;
    check_status(hs_verified_channel_valid(pv1, &channel_valid), HS_STATUS_OK,
                 "survive verified handle after channel close");
    check(channel_valid == 0, "channel close invalidates verified handle");
    check_status(hs_channel_send(p1, reinterpret_cast<const uint8_t*>(msg),
                                 static_cast<uint32_t>(std::strlen(msg))),
                 HS_STATUS_HANDSHAKE, "survive send denied after channel close");
    check_status(hs_channel_poll(p1, rbuf, sizeof rbuf, &rlen),
                 HS_STATUS_HANDSHAKE, "survive receive denied after channel close");
    check_status(hs_peer_close(p1), HS_STATUS_OK, "survive peer1 close");
    check_status(hs_peer_close(p2), HS_STATUS_OK, "survive peer2 close");
    uint32_t f1 = hs_peer_free(p1);
    check(f1 == HS_STATUS_OK || f1 == HS_STATUS_TIMEOUT, "survive peer1 free");
    uint32_t f2 = hs_peer_free(p2);
    check(f2 == HS_STATUS_OK || f2 == HS_STATUS_TIMEOUT, "survive peer2 free");
    uint32_t sb = hs_engine_shutdown(eng_b);
    check(sb == HS_STATUS_OK || sb == HS_STATUS_TIMEOUT, "survive engine B shutdown");
    check(hs_engine_shutdown(eng_b) == HS_STATUS_NULL, "survive double-shutdown B null");
  }

  // One reinitialization round: a fresh engine after both previous engines
  // were destroyed must still connect (library startup remains valid).
  {
    hs_engine* e = nullptr;
    check_status(hs_engine_init(&e), HS_STATUS_OK, "reinit engine init");
    hs_peer* a = nullptr;
    hs_peer* b = nullptr;
    check_status(hs_peer_create(e, &a), HS_STATUS_OK, "reinit peer1 create");
    check_status(hs_peer_create(e, &b), HS_STATUS_OK, "reinit peer2 create");
    check_status(hs_channel_create(a, HS_PRODUCT_CHANNEL_LABEL,
                                   std::strlen(HS_PRODUCT_CHANNEL_LABEL)),
                 HS_STATUS_OK, "reinit channel create");
    char off[HS_MAX_SDP_BYTES];
    size_t off_len = 0;
    check_status(hs_peer_create_offer(a, off, sizeof off, &off_len),
                 HS_STATUS_OK, "reinit offer");
    check_status(hs_peer_set_remote(b, "offer", 5, off, off_len),
                 HS_STATUS_OK, "reinit set remote offer");
    char ans[HS_MAX_SDP_BYTES];
    size_t ans_len = 0;
    check_status(hs_peer_create_answer(b, ans, sizeof ans, &ans_len),
                 HS_STATUS_OK, "reinit answer");
    check_status(hs_peer_set_remote(a, "answer", 6, ans, ans_len),
                 HS_STATUS_OK, "reinit set remote answer");
    exchange_ice(a, b, 30);
    bool open = wait_until([&] { return channel_open(a) && channel_open(b); },
                           15000);
    check(open, "reinit peers connected");
    hs_peer_close(a);
    hs_peer_close(b);
    hs_peer_free(a);
    hs_peer_free(b);
    uint32_t sd = hs_engine_shutdown(e);
    check(sd == HS_STATUS_OK || sd == HS_STATUS_TIMEOUT, "reinit engine shutdown");
  }

  // Deterministic failed-barrier seam: timeout must retain ownership and
  // report TIMEOUT; a later proven drain/free cleans up. Observers must not
  // be disposed while the barrier cannot complete.
  {
    hs_engine* e = nullptr;
    check_status(hs_engine_init(&e), HS_STATUS_OK, "fault engine init");
    hs_peer* p = nullptr;
    check_status(hs_peer_create(e, &p), HS_STATUS_OK, "fault peer create");
    check_status(hs_peer_close(p), HS_STATUS_OK, "fault peer close");

    hs_test_force_drain_timeout(1);
    uint32_t d = hs_peer_drain(p, 100);
    check(d == HS_STATUS_TIMEOUT, "fault drain reports TIMEOUT");
    uint32_t st = 0;
    check(hs_peer_state(p, &st) == HS_STATUS_OK,
          "fault peer handle retained after timeout");
    // One free on the retained peer must also fail closed (still no quiescence).
    uint32_t fr = hs_peer_free(p);
    check(fr == HS_STATUS_TIMEOUT, "fault free reports TIMEOUT while blocked");

    hs_test_force_drain_timeout(0);
    // Release the block: a later drain may retire; then free if still present.
    uint32_t d2 = hs_peer_drain(p, 3000);
    check(d2 == HS_STATUS_OK || d2 == HS_STATUS_TIMEOUT, "fault drain after release");
    uint32_t fr2 = hs_peer_free(p);
    if (d2 == HS_STATUS_OK) {
      check(fr2 == HS_STATUS_NULL, "fault free NULL after retiring drain");
    } else {
      check(fr2 == HS_STATUS_OK || fr2 == HS_STATUS_TIMEOUT,
            "fault free after second timeout");
    }
    uint32_t sd = hs_engine_shutdown(e);
    check(sd == HS_STATUS_OK || sd == HS_STATUS_TIMEOUT, "fault engine shutdown");
  }

  std::printf("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
