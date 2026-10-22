// hs_webrtc_bridge.cpp - Helicoid E01 ABI-3 subset on Google WebRTC.
//
// Explicit engine initialization, owned peer lifecycle, offer/answer + ICE,
// bounded data-channel product messages behind a verified-channel binding,
// channel-evidence from the actual negotiated DTLS peer certificate, and
// honest drain/close.
//
// Handle model (coordinator reviews 2026-10-14 and 2026-10-15):
//   Opaque hs_* handles are process-global monotonic registry tokens cast to
//   pointers. Caller memory is NEVER dereferenced. Every call looks the token
//   up in an owned registry. Tokens are globally unique across all engines and
//   are never reused; wrap/exhaustion denies. Release removes every owning
//   registry entry and the object, so allocator address reuse cannot revive
//   authority.
//
//   Drain barriers use heap-owned state captured by value (shared_ptr). A
//   timeout leaves the barrier alive for the late callback. Current-thread
//   drain never self-waits. A timeout does NOT authorize unsafe disposal:
//   observers and peers stay owned until a barrier actually returns, or are
//   retained in pending teardown.
//
//   PeerConnection / DataChannel scoped_refptr fields are only touched under
//   the peer api mutex (or on the WebRTC threads while holding it). Callbacks
//   hold the peer via weak_ptr, never a raw pointer.
//
// Peer identity is taken ONLY from DtlsTransportInformation::remote_ssl_certificates()
// after DtlsTransportState::kConnected. A caller-provided SDP fingerprint string
// is never treated as verified identity. DTLS transport observation invalidates
// verified handles on failure, close, or certificate replacement.
//
// Bounded video and lease primitives exist, but CAP_CAPTURE / CAP_ADMISSION /
// CAP_MEDIA remain disabled until product hosts verify authority, wire physical
// capture and viewer display, and pass end-to-end runtime acceptance.

#include "hs_webrtc.h"
#include "channel_binding.h"
#include "secure_memory.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "api/create_modular_peer_connection_factory.h"
#include "api/data_channel_interface.h"
#include "api/dtls_transport_interface.h"
#include "api/enable_media_with_defaults.h"
#include "api/environment/environment_factory.h"
#include "api/jsep.h"
#include "api/make_ref_counted.h"
#include "api/rtp_transceiver_interface.h"
#include "api/peer_connection_interface.h"
#include "api/scoped_refptr.h"
#include "api/sctp_transport_interface.h"
#include "api/stats/rtc_stats_collector_callback.h"
#include "api/stats/rtc_stats_report.h"
#include "api/stats/rtcstats_objects.h"
#include "api/video/adapted_video_track_source.h"
#include "api/video/i420_buffer.h"
#include "api/video/video_frame.h"
#include "api/video/video_sink_interface.h"
#include "rtc_base/buffer.h"
#include "rtc_base/rtc_certificate.h"
#include "rtc_base/rtc_certificate_generator.h"
#include "rtc_base/ssl_adapter.h"
#include "rtc_base/ssl_certificate.h"
#include "rtc_base/ssl_identity.h"
#include "rtc_base/thread.h"
#include "third_party/libyuv/include/libyuv/convert_argb.h"
#include "third_party/libyuv/include/libyuv/convert.h"
#if defined(WEBRTC_WIN)
#include "rtc_base/win32_socket_init.h"
#endif


// Export the C ABI with default visibility. The Chromium toolchain builds with
// -fvisibility=hidden; without this the dylib exports nothing.
// Three-mode export macro:
//   HS_WEBRTC_STATIC  -> no dllimport/dllexport (static bridge + its harness)
//   HS_WEBRTC_EXPORTS -> dllexport (building the shared library)
//   neither           -> dllimport (consuming the shared library)
#if defined(_WIN32)
  #if defined(HS_WEBRTC_STATIC)
    #define HS_API
  #elif defined(HS_WEBRTC_EXPORTS)
    #define HS_API __declspec(dllexport)
  #else
    #define HS_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define HS_API __attribute__((visibility("default")))
#else
  #define HS_API
#endif

namespace {

constexpr size_t kMaxIceQueue = HS_MAX_ICE_QUEUE;
constexpr size_t kMaxMsgQueue = HS_MAX_MSG_QUEUE;
constexpr const char* kPermittedProductLabel = HS_PRODUCT_CHANNEL_LABEL;
constexpr size_t kSha256Bytes = hs_webrtc_internal::kSha256Bytes;
constexpr uint32_t kMaxObservationLeaseMs = 30000;

using Token = uint64_t;
using Clock = std::chrono::steady_clock;

inline void* TokenToHandle(Token t) {
  return reinterpret_cast<void*>(static_cast<uintptr_t>(t));
}
inline Token HandleToToken(const void* h) {
  return static_cast<Token>(reinterpret_cast<uintptr_t>(h));
}

// Process-global monotonic token allocator. Tokens are unique across every
// engine and channel, never reused. Exhaustion denies.
std::atomic<Token> g_next_token{1};

bool AllocGlobalToken(Token* out) {
  if (!out) return false;
  Token t = g_next_token.fetch_add(1, std::memory_order_relaxed);
  // fetch_add wraps; deny the reserved 0 and any wrap past the top.
  if (t == 0 || t == UINT64_MAX) return false;
  *out = t;
  return true;
}

struct VerifiedChannel {
  Token token = 0;
  Token engine_token = 0;
  Token peer_token = 0;
  uint32_t generation = 0;
  uint64_t generation_id = 0;
  std::string peer_cert_pem;
  hs_webrtc_internal::ChannelBindingBytes channel_binding;
  std::atomic<bool> valid{true};

  void Invalidate() { valid.store(false, std::memory_order_release); }
  bool IsValid() const { return valid.load(std::memory_order_acquire); }
};

struct Peer;

class DesktopVideoSource : public webrtc::AdaptedVideoTrackSource {
 public:
  webrtc::MediaSourceInterface::SourceState state() const override {
    return webrtc::MediaSourceInterface::kLive;
  }
  bool remote() const override { return false; }
  bool is_screencast() const override { return true; }
  std::optional<bool> needs_denoising() const override { return false; }

  uint64_t Activate() {
    std::lock_guard<std::mutex> lock(submit_mu_);
    active_.store(false, std::memory_order_release);
    uint64_t current = generation_.load(std::memory_order_relaxed);
    if (current == std::numeric_limits<uint64_t>::max()) return 0;
    const uint64_t next = current + 1;
    generation_.store(next, std::memory_order_release);
    active_.store(true, std::memory_order_release);
    return next;
  }

  void Deactivate() {
    std::lock_guard<std::mutex> lock(submit_mu_);
    active_.store(false, std::memory_order_release);
    uint64_t current = generation_.load(std::memory_order_relaxed);
    if (current != std::numeric_limits<uint64_t>::max()) {
      generation_.store(current + 1, std::memory_order_release);
    }
  }

  uint32_t SubmitBgra(const uint8_t* bytes, uint32_t byte_count,
                      uint32_t width, uint32_t height, uint32_t stride,
                      uint64_t capture_generation) {
    if (!bytes) return HS_STATUS_NULL;
    if (!IsActive(capture_generation)) return HS_STATUS_HANDSHAKE;
    if (width == 0 || height == 0 || width > HS_MAX_SCREEN_FRAME_WIDTH ||
        height > HS_MAX_SCREEN_FRAME_HEIGHT ||
        stride < width * 4U) {
      return HS_STATUS_BOUNDS;
    }
    const uint64_t required_bytes = static_cast<uint64_t>(stride) * height;
    if (required_bytes != byte_count || required_bytes > HS_MAX_SCREEN_FRAME_BYTES) {
      return HS_STATUS_BOUNDS;
    }

    auto buffer = webrtc::I420Buffer::Create(static_cast<int>(width),
                                              static_cast<int>(height));
    if (!buffer) return HS_STATUS_INTERNAL;
    const int converted = libyuv::BGRAToI420(
        bytes, static_cast<int>(stride), buffer->MutableDataY(), buffer->StrideY(),
        buffer->MutableDataU(), buffer->StrideU(), buffer->MutableDataV(),
        buffer->StrideV(), static_cast<int>(width), static_cast<int>(height));
    if (converted != 0) return HS_STATUS_INVALID;
    std::lock_guard<std::mutex> lock(submit_mu_);
    if (!IsActive(capture_generation)) {
      webrtc::I420Buffer::SetBlack(buffer.get());
      return HS_STATUS_HANDSHAKE;
    }

    const auto timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now().time_since_epoch()).count();
    OnFrame(webrtc::VideoFrame::Builder()
                .set_video_frame_buffer(buffer)
                .set_timestamp_us(timestamp_us)
                .build());
    return HS_STATUS_OK;
  }

 private:
  bool IsActive(uint64_t generation) const {
    return generation != 0 && active_.load(std::memory_order_acquire) &&
           generation_.load(std::memory_order_acquire) == generation;
  }

  std::mutex submit_mu_;
  std::atomic<bool> active_{false};
  std::atomic<uint64_t> generation_{0};
};

class RemoteVideoSink final : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
  explicit RemoteVideoSink(std::weak_ptr<Peer> peer) : peer_(std::move(peer)) {}
  void OnFrame(const webrtc::VideoFrame& frame) override;

 private:
  std::weak_ptr<Peer> peer_;
};

class PeerObserver : public webrtc::PeerConnectionObserver {
 public:
  explicit PeerObserver(std::weak_ptr<Peer> peer) : peer_(std::move(peer)) {}
  void OnSignalingChange(
      webrtc::PeerConnectionInterface::SignalingState) override {}
  void OnDataChannel(
      webrtc::scoped_refptr<webrtc::DataChannelInterface> channel) override;
  void OnRenegotiationNeeded() override {}
  void OnIceConnectionChange(
      webrtc::PeerConnectionInterface::IceConnectionState state) override;
  void OnIceGatheringChange(
      webrtc::PeerConnectionInterface::IceGatheringState) override {}
  void OnIceCandidate(const webrtc::IceCandidate* candidate) override;
  void OnConnectionChange(
      webrtc::PeerConnectionInterface::PeerConnectionState state) override;
  void OnTrack(
      webrtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver) override;

 private:
  std::weak_ptr<Peer> peer_;
};

class ChannelObserver : public webrtc::DataChannelObserver {
 public:
  explicit ChannelObserver(std::weak_ptr<Peer> peer) : peer_(std::move(peer)) {}
  void OnStateChange() override;
  void OnMessage(const webrtc::DataBuffer& buffer) override;

 private:
  std::weak_ptr<Peer> peer_;
};

class DtlsObserver : public webrtc::DtlsTransportObserverInterface {
 public:
  explicit DtlsObserver(std::weak_ptr<Peer> peer) : peer_(std::move(peer)) {}
  void OnStateChange(webrtc::DtlsTransportInformation info) override;
  void OnError(webrtc::RTCError) override;

 private:
  std::weak_ptr<Peer> peer_;
};

// Shared TLS trust-invocation counters. Owned jointly by the Peer and the
// verifier so reads never race a dangling pointer after peer teardown, and so
// diagnostics remain available when TLS fails before any selected pair.
// calls/accepts/rejects come only from REAL verifier callbacks.
struct TurnTrustDiagnostics {
  std::atomic<uint32_t> calls{0};
  std::atomic<uint32_t> accepts{0};
  std::atomic<uint32_t> rejects{0};
};

struct Peer {
  Token token = 0;
  Token engine_token = 0;
  uint32_t generation = 0;
  uint64_t generation_id = 0;
  std::atomic<bool> closed{false};
  std::atomic<bool> drained{false};
  std::atomic<bool> dtls_failed{false};
  std::atomic<uint32_t> state{HS_PEER_STATE_NEW};

  // api mutex guards pc/dc/certificate/queues/handle and every ABI mutation.
  mutable std::mutex mu;
  webrtc::scoped_refptr<webrtc::RTCCertificate> certificate;
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
  webrtc::scoped_refptr<DesktopVideoSource> desktop_video_source;
  webrtc::scoped_refptr<webrtc::VideoTrackInterface> desktop_video_track;
  webrtc::scoped_refptr<webrtc::RtpTransceiverInterface> video_transceiver;
  webrtc::scoped_refptr<webrtc::VideoTrackInterface> remote_video_track;
  std::shared_ptr<RemoteVideoSink> remote_video_sink;
  bool video_prepared = false;
  uint32_t video_role = 0;
  bool negotiation_started = false;
  bool admission_active = false;
  bool capture_active = false;
  Token admission_channel_token = 0;
  uint64_t admission_generation_id = 0;
  uint64_t admission_generation = 0;
  uint64_t capture_generation = 0;
  Clock::time_point admission_deadline{};
  uint32_t remote_video_width = 0;
  uint32_t remote_video_height = 0;
  std::vector<uint8_t> remote_video_bgra;
  std::unique_ptr<PeerObserver> pc_observer;
  std::unique_ptr<ChannelObserver> dc_observer;
  std::shared_ptr<DtlsObserver> dtls_observer;
  webrtc::scoped_refptr<webrtc::DtlsTransportInterface> dtls;

  std::string expected_cert_pem;
  std::string negotiated_cert_pem;
  std::vector<std::string> local_ice;
  size_t local_ice_bytes = 0;
  bool ice_overflow = false;
  std::vector<std::string> inbound_msgs;
  size_t inbound_bytes = 0;
  bool inbound_overflow = false;
  std::shared_ptr<VerifiedChannel> vchan;
  // TURN TLS trust verifier diagnostics (lab evidence). Shared with the
  // verifier so counters never dangle and remain readable without a selected
  // route. Not negotiated identity and not admission.
  std::shared_ptr<TurnTrustDiagnostics> turn_trust_diag;
  bool turn_relay_only = false;

  std::weak_ptr<Peer> remote;  // in-process harness signaling only

  bool HasValidVChanLocked() const {
    return vchan && vchan->IsValid() && vchan->engine_token == engine_token &&
           vchan->peer_token == token && vchan->generation == generation &&
           vchan->generation_id == generation_id;
  }

  bool HasActiveAdmissionLocked(Clock::time_point now) const {
    return admission_active && now < admission_deadline && HasValidVChanLocked() &&
           vchan->token == admission_channel_token &&
           vchan->generation_id == admission_generation_id;
  }

  void ClearRemoteVideoLocked() {
    hs_webrtc_internal::SecureZero(remote_video_bgra);
    remote_video_bgra.clear();
    remote_video_width = 0;
    remote_video_height = 0;
  }

  void ClearMediaAdmissionLocked() {
    admission_active = false;
    capture_active = false;
    admission_channel_token = 0;
    admission_generation_id = 0;
    admission_deadline = Clock::time_point{};
    capture_generation = 0;
    if (admission_generation != std::numeric_limits<uint64_t>::max()) {
      ++admission_generation;
    }
    if (desktop_video_source) desktop_video_source->Deactivate();
    ClearRemoteVideoLocked();
  }

  void ClearInboundLocked() {
    inbound_msgs.clear();
    inbound_bytes = 0;
    inbound_overflow = false;
  }

  void InvalidateVChanLocked() {
    if (vchan) vchan->Invalidate();
    // Queued bytes were accepted under an earlier or absent identity binding.
    // Never release them after a later pin is installed.
    ClearInboundLocked();
    ClearMediaAdmissionLocked();
  }
  void RetireVChanLocked() {
    InvalidateVChanLocked();
    if (vchan) {
      vchan.reset();
    }
  }
};

void PeerObserver::OnIceConnectionChange(
    webrtc::PeerConnectionInterface::IceConnectionState state) {
  auto p = peer_.lock();
  if (!p) return;
  if (state == webrtc::PeerConnectionInterface::kIceConnectionFailed) {
    std::lock_guard<std::mutex> lock(p->mu);
    p->dtls_failed.store(true, std::memory_order_release);
    if (!p->closed.load()) {
      p->state.store(HS_PEER_STATE_FAILED, std::memory_order_release);
    }
    p->InvalidateVChanLocked();
  }
}

void PeerObserver::OnConnectionChange(
    webrtc::PeerConnectionInterface::PeerConnectionState state) {
  auto p = peer_.lock();
  if (!p) return;
  using PS = webrtc::PeerConnectionInterface::PeerConnectionState;
  if (state == PS::kConnected) {
    std::lock_guard<std::mutex> lock(p->mu);
    if (!p->closed.load()) {
      p->state.store(HS_PEER_STATE_CONNECTED, std::memory_order_release);
    }
  } else if (state == PS::kFailed) {
    std::lock_guard<std::mutex> lock(p->mu);
    p->dtls_failed.store(true, std::memory_order_release);
    if (!p->closed.load()) {
      p->state.store(HS_PEER_STATE_FAILED, std::memory_order_release);
    }
    p->InvalidateVChanLocked();
  } else if (state == PS::kClosed) {
    std::lock_guard<std::mutex> lock(p->mu);
    p->state.store(HS_PEER_STATE_CLOSED, std::memory_order_release);
    p->InvalidateVChanLocked();
  }
}

void PeerObserver::OnTrack(
    webrtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver) {
  auto p = peer_.lock();
  if (!p || !transceiver) return;
  auto receiver = transceiver->receiver();
  if (!receiver) return;
  auto media_track = receiver->track();
  if (!media_track ||
      media_track->kind() != webrtc::MediaStreamTrackInterface::kVideoKind) {
    return;
  }

  webrtc::scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(media_track.get()));
  auto sink = std::make_shared<RemoteVideoSink>(p);
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load() || !p->video_prepared ||
        p->video_role != HS_VIDEO_ROLE_RECEIVE_ONLY || p->remote_video_track) {
      return;
    }
    p->remote_video_track = video_track;
    p->remote_video_sink = sink;
  }
  video_track->AddOrUpdateSink(sink.get(), webrtc::VideoSinkWants{});
}

void RemoteVideoSink::OnFrame(const webrtc::VideoFrame& frame) {
  auto p = peer_.lock();
  if (!p) return;
  uint64_t admission_generation = 0;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load() || !p->HasActiveAdmissionLocked(Clock::now())) return;
    admission_generation = p->admission_generation;
  }

  auto buffer = frame.video_frame_buffer()->ToI420();
  if (!buffer) return;
  if (frame.rotation() != webrtc::kVideoRotation_0) {
    buffer = webrtc::I420Buffer::Rotate(*buffer, frame.rotation());
  }
  const uint32_t width = static_cast<uint32_t>(buffer->width());
  const uint32_t height = static_cast<uint32_t>(buffer->height());
  if (width == 0 || height == 0 || width > HS_MAX_SCREEN_FRAME_WIDTH ||
      height > HS_MAX_SCREEN_FRAME_HEIGHT) {
    return;
  }
  const uint64_t byte_count = static_cast<uint64_t>(width) * height * 4U;
  if (byte_count > HS_MAX_SCREEN_FRAME_BYTES) return;
  std::vector<uint8_t> pixels(static_cast<size_t>(byte_count));
  const int converted = libyuv::I420ToARGB(
      buffer->DataY(), buffer->StrideY(), buffer->DataU(), buffer->StrideU(),
      buffer->DataV(), buffer->StrideV(), pixels.data(),
      static_cast<int>(width * 4U), static_cast<int>(width),
      static_cast<int>(height));
  if (converted != 0) return;

  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load() ||
      p->admission_generation != admission_generation ||
      !p->HasActiveAdmissionLocked(Clock::now())) {
    hs_webrtc_internal::SecureZero(pixels);
    return;
  }
  p->ClearRemoteVideoLocked();
  p->remote_video_width = width;
  p->remote_video_height = height;
  p->remote_video_bgra = std::move(pixels);
}

void PeerObserver::OnIceCandidate(const webrtc::IceCandidate* candidate) {
  auto p = peer_.lock();
  if (!p || !candidate) return;
  std::string sdp = candidate->ToString();
  if (sdp.empty() || sdp.size() > HS_MAX_SDP_BYTES) return;

  std::shared_ptr<Peer> remote_peer;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return;
    if (p->local_ice.size() >= kMaxIceQueue ||
        p->local_ice_bytes + sdp.size() >
            kMaxIceQueue * (HS_MAX_SDP_BYTES / 8 + 1)) {
      p->ice_overflow = true;
      return;
    }
    p->local_ice.push_back(sdp);
    p->local_ice_bytes += sdp.size();
    remote_peer = p->remote.lock();
  }
  if (!remote_peer) return;
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> rpc;
  {
    std::lock_guard<std::mutex> rlock(remote_peer->mu);
    rpc = remote_peer->pc;
  }
  if (!rpc) return;
  webrtc::SdpParseError err;
  auto parsed = webrtc::IceCandidate::Create(
      candidate->sdp_mid(), candidate->sdp_mline_index(), sdp, &err);
  if (parsed) rpc->AddIceCandidate(parsed.get());
}

void PeerObserver::OnDataChannel(
    webrtc::scoped_refptr<webrtc::DataChannelInterface> channel) {
  auto p = peer_.lock();
  if (!p || !channel) return;
  if (channel->label() != kPermittedProductLabel) {
    channel->Close();
    return;
  }
  bool accepted = false;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (!p->closed.load() && !p->dc) {
      p->dc = channel;
      p->dc_observer = std::make_unique<ChannelObserver>(p);
      channel->RegisterObserver(p->dc_observer.get());
      if (channel->state() == webrtc::DataChannelInterface::kOpen) {
        p->state.store(HS_PEER_STATE_CHANNEL_OPEN, std::memory_order_release);
      }
      accepted = true;
    }
  }
  if (!accepted) channel->Close();
}

void ChannelObserver::OnStateChange() {
  auto p = peer_.lock();
  if (!p) return;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->dc && p->dc->state() == webrtc::DataChannelInterface::kOpen) {
    p->state.store(HS_PEER_STATE_CHANNEL_OPEN, std::memory_order_release);
  } else if (p->dc &&
             p->dc->state() == webrtc::DataChannelInterface::kClosed) {
    p->InvalidateVChanLocked();
    p->state.store(HS_PEER_STATE_CONNECTED, std::memory_order_release);
  }
}

void ChannelObserver::OnMessage(const webrtc::DataBuffer& buffer) {
  auto p = peer_.lock();
  if (!p) return;
  const size_t n = buffer.data.size();
  std::lock_guard<std::mutex> lock(p->mu);
  // DTLS encrypts the channel, but the remote identity is not established
  // until the negotiated certificate is pinned. Drop early data instead of
  // queueing it for a future verified session.
  if (!p->HasValidVChanLocked() || p->dtls_failed.load()) return;
  if (n > HS_MAX_MSG_BYTES) {
    p->inbound_overflow = true;
    return;
  }
  if (p->inbound_msgs.size() >= kMaxMsgQueue ||
      p->inbound_bytes + n > kMaxMsgQueue * HS_MAX_MSG_BYTES) {
    p->inbound_overflow = true;
    return;
  }
  p->inbound_msgs.emplace_back(buffer.data.data<char>(), n);
  p->inbound_bytes += n;
}

void DtlsObserver::OnStateChange(webrtc::DtlsTransportInformation info) {
  auto p = peer_.lock();
  if (!p) return;
  std::lock_guard<std::mutex> lock(p->mu);
  using S = webrtc::DtlsTransportState;
  if (info.state() != S::kConnected) {
    p->negotiated_cert_pem.clear();
    p->InvalidateVChanLocked();
  }
  if (info.state() == S::kFailed || info.state() == S::kClosed) {
    p->dtls_failed.store(true, std::memory_order_release);
  } else if (info.state() == S::kConnected) {
    const webrtc::SSLCertChain* chain = info.remote_ssl_certificates();
    std::string pem =
        (chain && chain->GetSize() > 0) ? chain->Get(0).ToPEMString() : std::string();
    // Certificate replacement (or first binding) invalidates old handles.
    if (!p->negotiated_cert_pem.empty() && p->negotiated_cert_pem != pem) {
      p->InvalidateVChanLocked();
    }
    p->negotiated_cert_pem = pem;
    if (!p->expected_cert_pem.empty() && p->expected_cert_pem != pem) {
      p->InvalidateVChanLocked();
    }
  }
}

void DtlsObserver::OnError(webrtc::RTCError) {
  auto p = peer_.lock();
  if (!p) return;
  std::lock_guard<std::mutex> lock(p->mu);
  p->dtls_failed.store(true, std::memory_order_release);
  p->InvalidateVChanLocked();
}

bool ExtractNegotiatedPeerCert(
    webrtc::PeerConnectionInterface* pc, std::string* out_pem,
    std::array<uint8_t, kSha256Bytes>* out_fingerprint) {
  if (!pc || !out_pem || !out_fingerprint) return false;
  auto sctp = pc->GetSctpTransport();
  if (!sctp) return false;
  auto dtls = sctp->dtls_transport();
  if (!dtls) return false;
  webrtc::DtlsTransportInformation info = dtls->Information();
  if (info.state() != webrtc::DtlsTransportState::kConnected) return false;
  const webrtc::SSLCertChain* chain = info.remote_ssl_certificates();
  if (!chain || chain->GetSize() == 0) return false;

  webrtc::Buffer digest = webrtc::Buffer::CreateWithCapacity(kSha256Bytes);
  const webrtc::SSLCertificate& leaf = chain->Get(0);
  if (!leaf.ComputeDigest("sha-256", digest) || digest.size() != kSha256Bytes) {
    return false;
  }
  std::copy(digest.data(), digest.data() + digest.size(), out_fingerprint->begin());
  *out_pem = leaf.ToPEMString();
  return !out_pem->empty();
}

// Heap-owned drain barrier. Captured by value; safe if the waiter times out
// and the task runs later.
struct DrainBarrier {
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
};

bool DrainWebRtcThread(webrtc::Thread* thread, Clock::time_point deadline) {
  if (!thread) return true;
  // Never self-wait on the thread that would run the barrier.
  if (thread->IsCurrent()) return true;

  auto barrier = std::make_shared<DrainBarrier>();
  thread->PostTask([barrier] {
    {
      std::lock_guard<std::mutex> lk(barrier->mu);
      barrier->done = true;
    }
    barrier->cv.notify_one();
  });
  std::unique_lock<std::mutex> lk(barrier->mu);
  return barrier->cv.wait_until(lk, deadline, [&] { return barrier->done; });
}

#if defined(HS_TEST_DRAIN_FAULT)
// Test-only seam compiled into the harness static bridge (not shared ABI).
// Forces DrainBoth to report a failed barrier so timeout retention can be
// exercised without hanging the real worker queue.
static std::atomic<int> g_hs_test_force_drain_timeout{0};
extern "C" void hs_test_force_drain_timeout(int on) {
  g_hs_test_force_drain_timeout.store(on ? 1 : 0);
}
#endif

bool DrainBoth(webrtc::Thread* signaling, webrtc::Thread* network,
               uint32_t timeout_ms) {
#if defined(HS_TEST_DRAIN_FAULT)
  if (g_hs_test_force_drain_timeout.load()) return false;
#endif
  auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
  bool ok_s = DrainWebRtcThread(signaling, deadline);
  bool ok_n = DrainWebRtcThread(network, deadline);
  return ok_s && ok_n;
}

// Run fn on the WebRTC signaling thread and wait up to timeout_ms. Returns
// false on timeout (fn may still run later; callers must not free state that
// fn captures until a later successful quiesce).
template <typename Fn>
bool InvokeOnSignaling(webrtc::Thread* signaling, Fn&& fn, uint32_t timeout_ms) {
  if (!signaling) return false;
  if (signaling->IsCurrent()) {
    fn();
    return true;
  }
  auto barrier = std::make_shared<DrainBarrier>();
  signaling->PostTask([barrier, fn = std::forward<Fn>(fn)]() mutable {
    fn();
    {
      std::lock_guard<std::mutex> lk(barrier->mu);
      barrier->done = true;
    }
    barrier->cv.notify_one();
  });
  std::unique_lock<std::mutex> lk(barrier->mu);
  return barrier->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                              [&] { return barrier->done; });
}


class SyncCreateDesc : public webrtc::CreateSessionDescriptionObserver {
 public:
  void OnSuccess(webrtc::SessionDescriptionInterface* desc) override {
    {
      std::lock_guard<std::mutex> lk(m_);
      if (desc) {
        sdp_ = desc->ToString();
        owned_.reset(desc);
      }
      ok_ = true;
      done_ = true;
    }
    cv_.notify_one();
  }
  void OnFailure(webrtc::RTCError) override {
    {
      std::lock_guard<std::mutex> lk(m_);
      done_ = true;
    }
    cv_.notify_one();
  }
  bool Wait(uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(m_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                        [this] { return done_; });
  }
  bool ok() const { return ok_; }
  std::string sdp() const { return sdp_; }
  webrtc::SessionDescriptionInterface* TakeDesc() { return owned_.release(); }

 private:
  std::mutex m_;
  std::condition_variable cv_;
  bool done_ = false;
  bool ok_ = false;
  std::string sdp_;
  std::unique_ptr<webrtc::SessionDescriptionInterface> owned_;
};

class SyncSetDesc : public webrtc::SetRemoteDescriptionObserverInterface {
 public:
  void OnSetRemoteDescriptionComplete(webrtc::RTCError error) override {
    {
      std::lock_guard<std::mutex> lk(m_);
      ok_ = error.ok();
      done_ = true;
    }
    cv_.notify_one();
  }
  bool Wait(uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(m_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                        [this] { return done_; });
  }
  bool ok() const { return ok_; }

 private:
  std::mutex m_;
  std::condition_variable cv_;
  bool done_ = false;
  bool ok_ = false;
};

class DummySetLocal : public webrtc::SetSessionDescriptionObserver {
 public:
  void OnSuccess() override {}
  void OnFailure(webrtc::RTCError) override {}
};

struct Engine {
  Token token = 0;
  std::atomic<bool> shut{false};
#if defined(WEBRTC_WIN)
  // Process/library startup owned by this engine. WSAStartup is OS-refcounted;
  // each live engine holds one initializer for its full lifetime (see
  // examples/peerconnection/client and test/test_main_lib.cc).
  std::unique_ptr<webrtc::WinsockInitializer> winsock;
#endif
  std::unique_ptr<webrtc::Thread> network_thread;
  std::unique_ptr<webrtc::Thread> signaling_thread;
  std::optional<webrtc::Environment> env;
  webrtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface> factory;

  std::mutex mu;
  std::unordered_map<Token, std::shared_ptr<Peer>> peers;
  std::unordered_map<Token, std::shared_ptr<VerifiedChannel>> vchans;
  uint32_t next_generation = 1;
  uint64_t next_generation_id = 1;
  // Retained when a drain barrier timed out; disposed on a later successful
  // quiesce or process exit. Timeout never authorizes unsafe disposal.
  // Unique pending-teardown peers keyed by token; bounded and cleaned after
  // proven thread quiescence. Never unbounded, never duplicated.
  std::unordered_map<Token, std::shared_ptr<Peer>> pending_teardown;

  std::shared_ptr<Peer> FindPeer(Token t) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = peers.find(t);
    return it == peers.end() ? nullptr : it->second;
  }
  std::shared_ptr<VerifiedChannel> FindVChan(Token t) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = vchans.find(t);
    return it == vchans.end() ? nullptr : it->second;
  }
  void RetireVChan(Token t) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = vchans.find(t);
    if (it != vchans.end()) {
      if (it->second) it->second->Invalidate();
      vchans.erase(it);
    }
  }
  void RetirePeer(Token t) {
    std::lock_guard<std::mutex> lock(mu);
    peers.erase(t);
  }
};

std::mutex g_engines_mu;
std::unordered_map<Token, std::shared_ptr<Engine>> g_engines;

// Process-wide SSL lifetime. Concurrent engines share one OpenSSL session;
// CleanupSSL runs only when the last engine releases. Failure paths release
// what they acquired so init errors cannot leak a reference.
std::mutex g_ssl_mu;
int g_ssl_refs = 0;

bool SslAcquire() {
  std::lock_guard<std::mutex> lock(g_ssl_mu);
  if (g_ssl_refs == 0) {
    if (!webrtc::InitializeSSL()) return false;
  }
  ++g_ssl_refs;
  return true;
}

void SslRelease() {
  std::lock_guard<std::mutex> lock(g_ssl_mu);
  if (g_ssl_refs <= 0) return;
  --g_ssl_refs;
  if (g_ssl_refs == 0) {
    webrtc::CleanupSSL();
  }
}

std::shared_ptr<Engine> FindEngine(Token t) {
  std::lock_guard<std::mutex> lock(g_engines_mu);
  auto it = g_engines.find(t);
  return it == g_engines.end() ? nullptr : it->second;
}

// Global peer/vchan indexes use the same global tokens as the engines, so two
// live engines can never collide.
std::mutex g_registry_mu;
std::unordered_map<Token, std::shared_ptr<Peer>> g_peer_index;
std::unordered_map<Token, std::shared_ptr<VerifiedChannel>> g_vchan_index;

// Process-level retained peers when a drain barrier timed out. Unique by
// token, bounded by live peer count, cleaned after proven quiescence.
std::mutex g_retained_mu;
std::unordered_map<Token, std::shared_ptr<Peer>> g_retained_peers;

std::shared_ptr<Peer> FindPeerGlobal(Token t) {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  auto it = g_peer_index.find(t);
  return it == g_peer_index.end() ? nullptr : it->second;
}
std::shared_ptr<VerifiedChannel> FindVChanGlobal(Token t) {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  auto it = g_vchan_index.find(t);
  return it == g_vchan_index.end() ? nullptr : it->second;
}
void RetirePeerGlobal(Token t) {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  g_peer_index.erase(t);
}
void RetireVChanGlobal(Token t) {
  std::lock_guard<std::mutex> lock(g_registry_mu);
  g_vchan_index.erase(t);
}

// Release a peer from every owner. If the drain barrier cannot complete the
// object is kept alive (no observer UAF) instead of being freed.
enum class PeerRetire { Released, Retained, Missing };

PeerRetire RetirePeerFully(const std::shared_ptr<Peer>& p, uint32_t timeout_ms) {
  if (!p) return PeerRetire::Missing;

  if (!p->closed.exchange(true, std::memory_order_acq_rel)) {
    // Close first so no new channel/ICE work is scheduled.
    // Unregister observers BEFORE destroying them so no registered raw
    // callback pointer outlives its observer object.
    webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
    webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
    webrtc::scoped_refptr<webrtc::VideoTrackInterface> remote_video_track;
    std::shared_ptr<RemoteVideoSink> remote_video_sink;
    std::unique_ptr<ChannelObserver> dc_obs;
    {
      std::lock_guard<std::mutex> lock(p->mu);
      p->state.store(HS_PEER_STATE_CLOSED, std::memory_order_release);
      p->InvalidateVChanLocked();
      dc = p->dc;
      pc = p->pc;
      remote_video_track = p->remote_video_track;
      remote_video_sink = p->remote_video_sink;
      p->dc = nullptr;
      dc_obs = std::move(p->dc_observer);
      p->RetireVChanLocked();
    }
    if (dc) {
      dc->UnregisterObserver();
      dc->Close();
    }
    dc_obs.reset();  // only after UnregisterObserver
    if (pc) {
      std::shared_ptr<Engine> e = FindEngine(p->engine_token);
      webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
      InvokeOnSignaling(sig, [pc, remote_video_track, remote_video_sink]() {
        if (remote_video_track && remote_video_sink) {
          remote_video_track->RemoveSink(remote_video_sink.get());
        }
        pc->Close();
      }, 5000);
    }
  }

  std::shared_ptr<Engine> e = FindEngine(p->engine_token);
  webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
  webrtc::Thread* net = e ? e->network_thread.get() : nullptr;

  bool drained_ok = DrainBoth(sig, net, timeout_ms);
  if (!drained_ok) {
    // Timeout must not authorize unsafe disposal or authority retirement.
    // Retain exactly once, keyed by token (no duplicate growth).
    if (e) {
      std::lock_guard<std::mutex> lock(e->mu);
      e->pending_teardown.emplace(p->token, p);
    }
    return PeerRetire::Retained;
  }

  // Barrier returned: safe to drop observers and pc. Unregister first.
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc_drop;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->dc) {
      p->dc->UnregisterObserver();
      p->dc->Close();
      p->dc = nullptr;
    }
    if (p->dtls) {
      p->dtls->UnregisterObserver();
      p->dtls = nullptr;
    }
    p->dc_observer.reset();
    p->dtls_observer.reset();
    pc_drop = p->pc;
    p->pc = nullptr;
    p->pc_observer.reset();
    p->RetireVChanLocked();
  }
  if (pc_drop) {
    InvokeOnSignaling(sig, [pc_drop]() { pc_drop->Close(); }, 2000);
    pc_drop = nullptr;
  }
  p->drained.store(true, std::memory_order_release);

  if (e) e->RetirePeer(p->token);
  RetirePeerGlobal(p->token);
  return PeerRetire::Released;
}


// Attempt to dispose retained peers now that thread quiescence is proven.
// Returns how many remain (bounded by live peer count). Safe to call again.
size_t DrainRetainedPeers(uint32_t timeout_ms) {
  std::vector<std::shared_ptr<Peer>> batch;
  {
    std::lock_guard<std::mutex> lock(g_retained_mu);
    for (auto& kv : g_retained_peers) batch.push_back(kv.second);
    g_retained_peers.clear();
  }
  size_t kept = 0;
  for (auto& p : batch) {
    if (!p) continue;
    std::shared_ptr<Engine> e = FindEngine(p->engine_token);
    webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
    webrtc::Thread* net = e ? e->network_thread.get() : nullptr;
    if (!DrainBoth(sig, net, timeout_ms)) {
      // Still not quiet: keep unique by token.
      std::lock_guard<std::mutex> lock(g_retained_mu);
      g_retained_peers.emplace(p->token, p);
      ++kept;
      continue;
    }
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->dc) {
      p->dc->UnregisterObserver();
      p->dc->Close();
      p->dc = nullptr;
    }
    if (p->dtls) {
      p->dtls->UnregisterObserver();
      p->dtls = nullptr;
    }
    p->dc_observer.reset();
    p->dtls_observer.reset();
    p->pc_observer.reset();
    if (p->pc) p->pc = nullptr;
    RetirePeerGlobal(p->token);
    if (e) e->RetirePeer(p->token);
  }
  return kept;
}

// Constant-time compare of equal-length public digests/DER. Length is not
// secret; content is. No early return on content mismatch.
bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t acc = 0;
  for (size_t i = 0; i < n; ++i) {
    acc = static_cast<uint8_t>(acc | (a[i] ^ b[i]));
  }
  return acc == 0;
}

// LAB TURN TLS trust: exact leaf PEM or SHA-256 DER pin. Never insecure.
// Rejects empty chain, parse failure, size mismatch, and digest mismatch.
// Production deployment trust remains separately gated; a caller fingerprint
// is not negotiated peer/channel identity.
class HsTurnTlsCertVerifier : public webrtc::SSLCertificateVerifier {
 public:
  HsTurnTlsCertVerifier(std::string expected_pem,
                        std::vector<uint8_t> expected_sha256,
                        std::shared_ptr<TurnTrustDiagnostics> diag)
      : expected_pem_(std::move(expected_pem)),
        expected_sha256_(std::move(expected_sha256)),
        diag_(std::move(diag)) {}

  bool VerifyChain(const webrtc::SSLCertChain& chain) override {
    if (diag_) diag_->calls.fetch_add(1, std::memory_order_relaxed);
    bool ok = false;
    if (chain.GetSize() == 0) {
      ok = false;
    } else {
      const webrtc::SSLCertificate& leaf = chain.Get(0);
      if (!expected_sha256_.empty()) {
        // Buffer must have capacity before ComputeDigest (0-capacity fails).
        webrtc::Buffer digest = webrtc::Buffer::CreateWithCapacity(32);
        if (leaf.ComputeDigest("sha-256", digest) &&
            digest.size() == expected_sha256_.size()) {
          ok = ConstantTimeEqual(digest.data(), expected_sha256_.data(),
                                 digest.size());
        }
      } else if (!expected_pem_.empty()) {
        auto expected = webrtc::SSLCertificate::FromPEMString(expected_pem_);
        if (expected) {
          webrtc::Buffer expected_der;
          expected->ToDER(&expected_der);
          webrtc::Buffer leaf_der;
          leaf.ToDER(&leaf_der);
          if (expected_der.size() != 0 &&
              expected_der.size() == leaf_der.size()) {
            ok = ConstantTimeEqual(expected_der.data(), leaf_der.data(),
                                   leaf_der.size());
          }
        }
      }
    }
    if (diag_) {
      if (ok) {
        diag_->accepts.fetch_add(1, std::memory_order_relaxed);
      } else {
        diag_->rejects.fetch_add(1, std::memory_order_relaxed);
      }
    }
    return ok;
  }

  // Never a blanket accept. Legacy path stays deny.
  bool Verify(const webrtc::SSLCertificate&) override {
    if (diag_) {
      diag_->calls.fetch_add(1, std::memory_order_relaxed);
      diag_->rejects.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
  }

 private:
  std::string expected_pem_;
  std::vector<uint8_t> expected_sha256_;
  std::shared_ptr<TurnTrustDiagnostics> diag_;
};

// Supported host grammar for the turns URI: IPv4 literal or DNS hostname.
// IPv6 is explicitly unsupported (rejected). Rejects embedded NUL/control/
// URI metacharacters so the value cannot break out of the turns URI.
bool HostFormAllowed(const char* host, uint32_t len) {
  if (!host || len == 0 || len > HS_MAX_TURN_HOST_BYTES) return false;
  // Explicitly reject IPv6 literals (bracketed or bare).
  for (uint32_t i = 0; i < len; ++i) {
    if (host[i] == '[' || host[i] == ']' || host[i] == ':') return false;
    const unsigned char c = static_cast<unsigned char>(host[i]);
    if (c == 0 || c < 0x20 || c == 0x7f) return false;
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '-';
    if (!ok) return false;
  }
  // Must contain at least one alphanumeric; must not start/end with dot/hyphen.
  const unsigned char first = static_cast<unsigned char>(host[0]);
  const unsigned char last = static_cast<unsigned char>(host[len - 1]);
  if (!(std::isalnum(first) || first == '_')) {
    if (first != '.') return false;
  }
  if (last == '.' || last == '-') return false;
  bool has_alnum = false;
  bool all_digits_dots = true;
  for (uint32_t i = 0; i < len; ++i) {
    const unsigned char c = static_cast<unsigned char>(host[i]);
    if (std::isalnum(c)) has_alnum = true;
    if (!(c >= '0' && c <= '9') && c != '.') all_digits_dots = false;
    if (c == '-' && (i == 0 || host[i - 1] == '.')) return false;
    if (c == '.' && i + 1 < len && host[i + 1] == '.') return false;
  }
  if (!has_alnum) return false;
  // IPv4-ish form: only digits and dots (bounded 4 labels).
  if (all_digits_dots) {
    uint32_t labels = 1;
    for (uint32_t i = 0; i < len; ++i) {
      if (host[i] == '.') labels++;
    }
    if (labels != 4) return false;
  }
  return true;
}

bool BoundedFieldOk(const char* p, uint32_t len, uint32_t max) {
  if (!p || len == 0 || len > max) return false;
  for (uint32_t i = 0; i < len; ++i) {
    const unsigned char c = static_cast<unsigned char>(p[i]);
    if (c == 0) return false;
  }
  return true;
}

// Exact size/version and bounded credential/trust validation. Rejects
// malformed/null/overflow/unsupported input before any authority is created.
// Pointer/length pairs must be consistent on BOTH trust fields so a valid SHA
// input cannot hide a nonzero malformed PEM and vice versa.
uint32_t ValidateTurnConfig(const hs_turn_tls_config* cfg,
                            std::string* out_host, std::string* out_user,
                            std::string* out_pass, std::string* out_pem,
                            std::vector<uint8_t>* out_sha256) {
  if (!cfg || !out_host || !out_user || !out_pass || !out_pem || !out_sha256) {
    return HS_STATUS_NULL;
  }
  if (cfg->struct_size != sizeof(hs_turn_tls_config)) return HS_STATUS_INVALID;
  if (cfg->version != HS_TURN_CONFIG_VERSION) return HS_STATUS_INVALID;
  if (cfg->host_len == 0 || cfg->host_len > HS_MAX_TURN_HOST_BYTES) {
    return HS_STATUS_BOUNDS;
  }
  if (!HostFormAllowed(cfg->host, cfg->host_len)) return HS_STATUS_INVALID;
  if (cfg->port == 0 || cfg->port > 65535u) return HS_STATUS_BOUNDS;
  if (!BoundedFieldOk(cfg->username, cfg->username_len, HS_MAX_TURN_USER_BYTES)) {
    return HS_STATUS_BOUNDS;
  }
  if (!BoundedFieldOk(cfg->password, cfg->password_len, HS_MAX_TURN_PASS_BYTES)) {
    return HS_STATUS_BOUNDS;
  }

  // Pointer/length consistency for every optional field.
  const bool pem_ptr = cfg->trust_pem != nullptr;
  const bool sha_ptr = cfg->trust_sha256 != nullptr;
  if (pem_ptr != (cfg->trust_pem_len > 0)) return HS_STATUS_INVALID;
  if (sha_ptr != (cfg->trust_sha256_len > 0)) return HS_STATUS_INVALID;
  if (cfg->trust_pem_len > 0 && cfg->trust_pem_len > HS_MAX_TURN_TRUST_PEM_BYTES) {
    return HS_STATUS_BOUNDS;
  }
  if (cfg->trust_sha256_len > 0 &&
      cfg->trust_sha256_len != HS_MAX_TURN_TRUST_SHA256) {
    return HS_STATUS_BOUNDS;
  }

  const bool has_pem = pem_ptr && cfg->trust_pem_len > 0;
  const bool has_sha = sha_ptr && cfg->trust_sha256_len > 0;
  // Exactly one trust mode. No trust is fail-closed; dual mode is unsupported.
  if (has_pem == has_sha) return HS_STATUS_INVALID;

  if (has_pem) {
    out_pem->assign(cfg->trust_pem, cfg->trust_pem_len);
    // Reject malformed PEM before creating a peer.
    auto parsed = webrtc::SSLCertificate::FromPEMString(*out_pem);
    if (!parsed) return HS_STATUS_INVALID;
    webrtc::Buffer der;
    parsed->ToDER(&der);
    if (der.size() == 0) return HS_STATUS_INVALID;
  } else {
    out_sha256->assign(cfg->trust_sha256,
                       cfg->trust_sha256 + HS_MAX_TURN_TRUST_SHA256);
  }
  out_host->assign(cfg->host, cfg->host_len);
  out_user->assign(cfg->username, cfg->username_len);
  out_pass->assign(cfg->password, cfg->password_len);
  return HS_STATUS_OK;
}

class SyncStatsCallback : public webrtc::RTCStatsCollectorCallback {
 public:
  void OnStatsDelivered(
      const webrtc::scoped_refptr<const webrtc::RTCStatsReport>& report) override {
    {
      std::lock_guard<std::mutex> lk(m_);
      report_ = report;
      done_ = true;
    }
    cv_.notify_one();
  }
  bool Wait(uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(m_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                        [this] { return done_; });
  }
  webrtc::scoped_refptr<const webrtc::RTCStatsReport> report() const {
    std::lock_guard<std::mutex> lk(m_);
    return report_;
  }

 private:
  mutable std::mutex m_;
  std::condition_variable cv_;
  bool done_ = false;
  webrtc::scoped_refptr<const webrtc::RTCStatsReport> report_;
};

// Selected pair/transport evidence from native stats. Offer/answer candidates
// alone are not selection evidence.
bool BuildSelectedTransportJson(webrtc::PeerConnectionInterface* pc,
                                std::string* out_json) {
  if (!pc || !out_json) return false;
  auto cb = webrtc::make_ref_counted<SyncStatsCallback>();
  pc->GetStats(cb.get());
  if (!cb->Wait(5000)) return false;
  webrtc::scoped_refptr<const webrtc::RTCStatsReport> report = cb->report();
  if (!report) return false;

  std::string selected_pair_id;
  std::string dtls_state;
  for (const auto& stats : *report) {
    if (stats.type() == std::string(webrtc::RTCTransportStats::kType)) {
      const auto& t = stats.cast_to<webrtc::RTCTransportStats>();
      if (t.selected_candidate_pair_id) {
        selected_pair_id = *t.selected_candidate_pair_id;
      }
      if (t.dtls_state) dtls_state = *t.dtls_state;
    }
  }
  if (selected_pair_id.empty()) return false;

  const webrtc::RTCIceCandidatePairStats* pair = nullptr;
  for (const auto& stats : *report) {
    if (stats.type() == std::string(webrtc::RTCIceCandidatePairStats::kType)) {
      const auto& p = stats.cast_to<webrtc::RTCIceCandidatePairStats>();
      if (p.id() == selected_pair_id) {
        pair = &p;
        break;
      }
    }
  }
  if (!pair || !pair->local_candidate_id || !pair->remote_candidate_id) {
    return false;
  }

  // Find selected local/remote candidates by exact stats subclass kType.
  // Never cast_to a mismatched type (debug RTC_DCHECK).
  struct CandFields {
    std::string type, protocol, relay_protocol, tcp_type, url, address;
  };
  auto fill_cand = [&](const std::string& id, bool want_local,
                       CandFields* out) -> bool {
    for (const auto& stats : *report) {
      const char* t = stats.type();
      const bool is_local =
          std::strcmp(t, webrtc::RTCLocalIceCandidateStats::kType) == 0;
      const bool is_remote =
          std::strcmp(t, webrtc::RTCRemoteIceCandidateStats::kType) == 0;
      if (want_local != is_local) continue;
      if (!is_local && !is_remote) continue;
      if (is_local) {
        const auto& c =
            stats.cast_to<webrtc::RTCLocalIceCandidateStats>();
        if (c.id() != id) continue;
        out->type = c.candidate_type ? *c.candidate_type : std::string();
        out->protocol = c.protocol ? *c.protocol : std::string();
        out->relay_protocol =
            c.relay_protocol ? *c.relay_protocol : std::string();
        out->tcp_type = c.tcp_type ? *c.tcp_type : std::string();
        out->url = c.url ? *c.url : std::string();
        out->address = c.address ? *c.address : std::string();
        return true;
      }
      const auto& c = stats.cast_to<webrtc::RTCRemoteIceCandidateStats>();
      if (c.id() != id) continue;
      out->type = c.candidate_type ? *c.candidate_type : std::string();
      out->protocol = c.protocol ? *c.protocol : std::string();
      out->relay_protocol =
          c.relay_protocol ? *c.relay_protocol : std::string();
      out->tcp_type = c.tcp_type ? *c.tcp_type : std::string();
      out->url = c.url ? *c.url : std::string();
      out->address = c.address ? *c.address : std::string();
      return true;
    }
    return false;
  };
  CandFields local, remote;
  if (!fill_cand(*pair->local_candidate_id, true, &local)) return false;
  if (!fill_cand(*pair->remote_candidate_id, false, &remote)) return false;

  auto jstr = [](const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
      if (c == '"' || c == '\\') {
        o += '\\';
        o += c;
      } else if (static_cast<unsigned char>(c) < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof buf, "\\u%04x", c);
        o += buf;
      } else {
        o += c;
      }
    }
    o += '"';
    return o;
  };
  auto cand_obj = [&](const CandFields& c) {
    std::string o = "{";
    o += "\"type\":" + jstr(c.type) + ",";
    o += "\"protocol\":" + jstr(c.protocol) + ",";
    o += "\"relay_protocol\":" + jstr(c.relay_protocol) + ",";
    o += "\"tcp_type\":" + jstr(c.tcp_type) + ",";
    o += "\"url\":" + jstr(c.url) + ",";
    o += "\"address\":" + jstr(c.address);
    o += "}";
    return o;
  };

  std::string json = "{";
  json += "\"dtls_state\":" + jstr(dtls_state) + ",";
  json += "\"selected_pair_id\":" + jstr(selected_pair_id) + ",";
  json += "\"local\":" + cand_obj(local) + ",";
  json += "\"remote\":" + cand_obj(remote);
  json += "}";
  if (json.size() > HS_MAX_SELECTED_JSON_BYTES) return false;
  *out_json = std::move(json);
  return true;
}

}  // namespace

extern "C" {

HS_API uint32_t hs_abi_version(void) { return HS_ABI_VERSION; }

HS_API const char* hs_engine_version(void) {
  return "hs-webrtc-native/0.3.0+e01-abi3-subset";
}

HS_API uint32_t hs_engine_capabilities(uint32_t* out_mask) {
  if (!out_mask) return HS_STATUS_NULL;
  *out_mask = HS_CAP_INITIALIZATION | HS_CAP_NEGOTIATION |
              HS_CAP_CHANNEL_EVIDENCE | HS_CAP_DRAIN;
#if defined(WEBRTC_EXCLUDE_BUILT_IN_SSL_ROOT_CERTS)
  // Exclusive-pin build mode only. Never advertise TURN TLS trust without it.
  *out_mask |= HS_CAP_TURN_TLS;
#endif
  return HS_STATUS_OK;
}

HS_API uint32_t hs_engine_init(hs_engine** out) {
  if (!out) return HS_STATUS_NULL;
  *out = nullptr;
  if (!SslAcquire()) return HS_STATUS_INTERNAL;

  Token etok;
  if (!AllocGlobalToken(&etok)) {
    SslRelease();
    return HS_STATUS_EXHAUSTED;
  }

  auto engine = std::make_shared<Engine>();
  engine->token = etok;
#if defined(WEBRTC_WIN)
  // Socket stack must be up before CreateWithSocketServer binds UDP for ICE.
  engine->winsock = std::make_unique<webrtc::WinsockInitializer>();
  if (engine->winsock->error() != 0) {
    engine->winsock.reset();
    SslRelease();
    return HS_STATUS_INTERNAL;
  }
#endif
  engine->network_thread = webrtc::Thread::CreateWithSocketServer();
  engine->signaling_thread = webrtc::Thread::Create();
  if (!engine->network_thread->Start() || !engine->signaling_thread->Start()) {
    SslRelease();
    return HS_STATUS_INTERNAL;
  }
  webrtc::EnvironmentFactory env_factory;
  engine->env = env_factory.Create();

  webrtc::PeerConnectionFactoryDependencies deps;
  deps.network_thread = engine->network_thread.get();
  deps.signaling_thread = engine->signaling_thread.get();
  deps.env = *engine->env;
  // Install the pinned default software codec factories required by the peer
  // factory. Product media capabilities remain unavailable until platform
  // capture, authority verification, and teardown pass end-to-end acceptance.
  webrtc::EnableMediaWithDefaults(deps);
  engine->factory = webrtc::CreateModularPeerConnectionFactory(std::move(deps));
  if (!engine->factory) {
    SslRelease();
    return HS_STATUS_INTERNAL;
  }

  {
    std::lock_guard<std::mutex> lock(g_engines_mu);
    g_engines.emplace(etok, engine);
  }
  *out = reinterpret_cast<hs_engine*>(TokenToHandle(etok));
  return HS_STATUS_OK;
}

HS_API uint32_t hs_engine_shutdown(hs_engine* h) {
  if (!h) return HS_STATUS_NULL;
  Token t = HandleToToken(h);
  std::shared_ptr<Engine> e;
  {
    std::lock_guard<std::mutex> lock(g_engines_mu);
    auto it = g_engines.find(t);
    if (it == g_engines.end()) return HS_STATUS_NULL;
    e = it->second;
    g_engines.erase(it);
  }
  if (e->shut.exchange(true)) return HS_STATUS_STATE;

  // Snapshot peers and channels; close callbacks must run before observers
  // are retired, so we close first, then barrier, then drop.
  std::vector<std::shared_ptr<Peer>> peers;
  std::vector<std::shared_ptr<VerifiedChannel>> vchans;
  {
    std::lock_guard<std::mutex> lock(e->mu);
    for (auto& kv : e->peers) peers.push_back(kv.second);
    for (auto& kv : e->vchans) vchans.push_back(kv.second);
    for (auto& kv : e->pending_teardown) peers.push_back(kv.second);
    e->peers.clear();
    e->vchans.clear();
    e->pending_teardown.clear();
  }
  for (auto& vc : vchans) {
    if (vc) {
      vc->Invalidate();
      RetireVChanGlobal(vc->token);
    }
  }

  for (auto& p : peers) {
    if (!p) continue;
    if (!p->closed.exchange(true, std::memory_order_acq_rel)) {
      webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
      webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
      std::unique_ptr<ChannelObserver> dc_obs;
      {
        std::lock_guard<std::mutex> lock(p->mu);
        p->state.store(HS_PEER_STATE_CLOSED, std::memory_order_release);
        p->InvalidateVChanLocked();
        dc = p->dc;
        pc = p->pc;
        p->dc = nullptr;
        dc_obs = std::move(p->dc_observer);
        p->RetireVChanLocked();
      }
      if (dc) {
        dc->UnregisterObserver();
        dc->Close();
      }
      dc_obs.reset();
      if (pc) {
        InvokeOnSignaling(e->signaling_thread.get(), [pc]() { pc->Close(); }, 5000);
      }
    }
  }

  // Barrier includes final close callbacks (Close() posts work on these threads).
  bool drained = DrainBoth(e->signaling_thread.get(), e->network_thread.get(), 5000);

  if (drained) {
    for (auto& p : peers) {
      if (!p) continue;
      std::lock_guard<std::mutex> lock(p->mu);
      if (p->dtls) {
        p->dtls->UnregisterObserver();
        p->dtls = nullptr;
      }
      p->dtls_observer.reset();
      p->pc_observer.reset();
      p->dc_observer.reset();
      if (p->pc) {
        p->pc = nullptr;
      }
    }
  }
  // If !drained, retain peers in a process-level UNIQUE token map so callbacks
  // cannot UAF. Bounded by live peer count; cleaned after a later proven
  // quiescence (see HsRetainedDrain). Never an unbounded vector.
  if (!drained) {
    std::lock_guard<std::mutex> lock(g_retained_mu);
    for (auto& p : peers) {
      if (p) g_retained_peers.emplace(p->token, p);
    }
  }
  peers.clear();
  vchans.clear();

  e->factory = nullptr;
  if (e->signaling_thread) e->signaling_thread->Stop();
  if (e->network_thread) e->network_thread->Stop();
  // Proven quiescence (threads stopped): dispose any retained peers.
  DrainRetainedPeers(1000);
#if defined(WEBRTC_WIN)
  // Drop Winsock only after the network thread is stopped so no socket
  // callback can run during WSACleanup.
  e->winsock.reset();
#endif
  SslRelease();
  // Engine object is kept alive by this shared_ptr until return; pending
  // teardown peers hold only weak observer links.
  return drained ? HS_STATUS_OK : HS_STATUS_TIMEOUT;
}

HS_API uint32_t hs_engine_drain(hs_engine* h, uint32_t timeout_ms) {
  if (!h) return HS_STATUS_NULL;
  Token t = HandleToToken(h);
  std::shared_ptr<Engine> e = FindEngine(t);
  if (!e) return HS_STATUS_NULL;
  bool ok = DrainBoth(e->signaling_thread.get(), e->network_thread.get(),
                      timeout_ms);
  if (ok) DrainRetainedPeers(timeout_ms);
  return ok ? HS_STATUS_OK : HS_STATUS_TIMEOUT;
}

HS_API uint32_t hs_peer_create(hs_engine* h, hs_peer** out) {
  if (!h || !out) return HS_STATUS_NULL;
  *out = nullptr;
  std::shared_ptr<Engine> e = FindEngine(HandleToToken(h));
  if (!e || e->shut.load()) return HS_STATUS_NULL;

  Token ptok;
  if (!AllocGlobalToken(&ptok)) return HS_STATUS_EXHAUSTED;

  uint32_t gen;
  uint64_t gen_id;
  {
    std::lock_guard<std::mutex> lock(e->mu);
    if (e->peers.size() >= 64) {
      return HS_STATUS_EXHAUSTED;
    }
    // Engine-local monotonic generation; wrap/exhaustion denies (no reuse).
    if (e->next_generation == 0 || e->next_generation == UINT32_MAX ||
        e->next_generation_id == 0 || e->next_generation_id == UINT64_MAX) {
      return HS_STATUS_EXHAUSTED;
    }
    gen = e->next_generation++;
    gen_id = e->next_generation_id++;
  }

  auto peer = std::make_shared<Peer>();
  peer->token = ptok;
  peer->engine_token = e->token;
  peer->generation = gen;
  peer->generation_id = gen_id;

  webrtc::KeyParams key_params = webrtc::KeyParams::ECDSA();
  peer->certificate = webrtc::RTCCertificateGenerator::GenerateCertificate(
      key_params, std::nullopt);
  if (!peer->certificate) return HS_STATUS_INTERNAL;

  peer->pc_observer = std::make_unique<PeerObserver>(peer);
  peer->turn_trust_diag = std::make_shared<TurnTrustDiagnostics>();
  webrtc::PeerConnectionInterface::RTCConfiguration config;
  config.certificates.push_back(peer->certificate);
  webrtc::PeerConnectionDependencies deps(peer->pc_observer.get());
  auto pc_or = e->factory->CreatePeerConnectionOrError(config, std::move(deps));
  if (!pc_or.ok()) return HS_STATUS_INTERNAL;
  peer->pc = pc_or.MoveValue();

  // Register DTLS observer when the transport appears (after negotiation).
  // We also attach eagerly via LookupDtlsTransportByMid after set_remote.

  {
    std::lock_guard<std::mutex> lock(e->mu);
    e->peers.emplace(ptok, peer);
  }
  {
    std::lock_guard<std::mutex> lock(g_registry_mu);
    g_peer_index.emplace(ptok, peer);
  }
  *out = reinterpret_cast<hs_peer*>(TokenToHandle(ptok));
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_close(hs_peer* h) {
  if (!h) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  webrtc::scoped_refptr<webrtc::VideoTrackInterface> remote_video_track;
  std::shared_ptr<RemoteVideoSink> remote_video_sink;
  std::unique_ptr<ChannelObserver> dc_obs;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.exchange(true, std::memory_order_acq_rel)) {
      return HS_STATUS_STATE;
    }
    p->state.store(HS_PEER_STATE_CLOSED, std::memory_order_release);
    p->InvalidateVChanLocked();
    dc = p->dc;
    pc = p->pc;
    remote_video_track = p->remote_video_track;
    remote_video_sink = p->remote_video_sink;
    p->dc = nullptr;
    dc_obs = std::move(p->dc_observer);
    p->RetireVChanLocked();
  }
  if (dc) {
    dc->UnregisterObserver();
    dc->Close();
  }
  dc_obs.reset();
  if (pc) {
    std::shared_ptr<Engine> e = FindEngine(p->engine_token);
    webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
    InvokeOnSignaling(sig, [pc, remote_video_track, remote_video_sink]() {
      if (remote_video_track && remote_video_sink) {
        remote_video_track->RemoveSink(remote_video_sink.get());
      }
      pc->Close();
    }, 5000);
  }
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_free(hs_peer* h) {
  if (!h) return HS_STATUS_NULL;
  Token t = HandleToToken(h);
  std::shared_ptr<Peer> p = FindPeerGlobal(t);
  if (!p) return HS_STATUS_NULL;
  if (!p->closed.load(std::memory_order_acquire)) return HS_STATUS_STATE;
  // Free requires a proven barrier. Timeout retains the object (no UAF).
  // After a successful retiring drain the registry entry is already gone, so
  // FindPeerGlobal fails closed with NULL (not a two-phase free guarantee).
  PeerRetire r = RetirePeerFully(p, 3000);
  if (r == PeerRetire::Retained) return HS_STATUS_TIMEOUT;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_generation(hs_peer* h, uint32_t* out_gen) {
  if (!h || !out_gen) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  *out_gen = p->generation;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_state(hs_peer* h, uint32_t* out_state) {
  if (!h || !out_state) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  *out_state = p->state.load(std::memory_order_acquire);
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_local_cert_export(hs_peer* h, uint8_t* out, uint32_t cap,
                                   uint32_t* out_len) {
  if (!h || !out || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  std::string pem;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (!p->certificate) return HS_STATUS_NULL;
    pem = p->certificate->GetSSLCertificate().ToPEMString();
  }
  if (pem.size() > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out, pem.data(), pem.size());
  *out_len = static_cast<uint32_t>(pem.size());
  return HS_STATUS_OK;
}

HS_API uint32_t hs_channel_create(hs_peer* h, const char* label, size_t label_len) {
  if (!h || !label) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  if (label_len == 0 || label_len > HS_MAX_LABEL_BYTES) return HS_STATUS_BOUNDS;
  std::string lbl(label, label_len);
  if (lbl != kPermittedProductLabel) return HS_STATUS_INVALID;

  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (p->dc) return HS_STATUS_STATE;
  if (!p->pc) return HS_STATUS_STATE;
  auto dc_or = p->pc->CreateDataChannelOrError(lbl, nullptr);
  if (!dc_or.ok()) return HS_STATUS_INTERNAL;
  auto channel = dc_or.MoveValue();
  p->dc = channel;
  p->dc_observer = std::make_unique<ChannelObserver>(p);
  channel->RegisterObserver(p->dc_observer.get());
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_video_prepare(hs_peer* h, uint32_t role) {
  if (!h) return HS_STATUS_NULL;
  if (role != HS_VIDEO_ROLE_SEND_ONLY && role != HS_VIDEO_ROLE_RECEIVE_ONLY) {
    return HS_STATUS_INVALID;
  }
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  std::shared_ptr<Engine> e = FindEngine(p->engine_token);
  if (!e || e->shut.load() || !e->factory) return HS_STATUS_STATE;

  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load() || !p->pc) return HS_STATUS_STATE;
  if (p->video_prepared || p->negotiation_started) return HS_STATUS_STATE;

  webrtc::RtpTransceiverInit init;
  if (role == HS_VIDEO_ROLE_SEND_ONLY) {
    init.direction = webrtc::RtpTransceiverDirection::kSendOnly;
    auto source = webrtc::make_ref_counted<DesktopVideoSource>();
    auto track = e->factory->CreateVideoTrack(source, "hs-desktop-screen");
    if (!track) return HS_STATUS_INTERNAL;
    auto transceiver = p->pc->AddTransceiver(track, init);
    if (!transceiver.ok()) return HS_STATUS_INTERNAL;
    p->desktop_video_source = std::move(source);
    p->desktop_video_track = std::move(track);
    p->video_transceiver = transceiver.MoveValue();
  } else {
    init.direction = webrtc::RtpTransceiverDirection::kRecvOnly;
    auto transceiver = p->pc->AddTransceiver(webrtc::MediaType::VIDEO, init);
    if (!transceiver.ok()) return HS_STATUS_INTERNAL;
    p->video_transceiver = transceiver.MoveValue();
  }
  p->video_role = role;
  p->video_prepared = true;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_create_offer(hs_peer* h, char* out_sdp, size_t cap,
                              size_t* out_len) {
  if (!h || !out_sdp || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;

  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return HS_STATUS_STATE;
    p->negotiation_started = true;
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;

  auto obs = webrtc::make_ref_counted<SyncCreateDesc>();
  webrtc::PeerConnectionInterface::RTCOfferAnswerOptions options;
  pc->CreateOffer(obs.get(), options);
  if (!obs->Wait(10000)) return HS_STATUS_TIMEOUT;
  if (!obs->ok()) return HS_STATUS_INTERNAL;

  webrtc::SessionDescriptionInterface* desc = obs->TakeDesc();
  if (!desc) return HS_STATUS_INTERNAL;
  // Classic overload takes raw observer + raw desc (ownership transferred).
  auto set_obs = webrtc::make_ref_counted<DummySetLocal>();
  pc->SetLocalDescription(set_obs.get(), desc);

  if (p->closed.load()) return HS_STATUS_STATE;
  std::string sdp = obs->sdp();
  if (sdp.empty() || sdp.size() + 1 > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out_sdp, sdp.c_str(), sdp.size() + 1);
  *out_len = sdp.size();
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_create_answer(hs_peer* h, char* out_sdp, size_t cap,
                               size_t* out_len) {
  if (!h || !out_sdp || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;

  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return HS_STATUS_STATE;
    p->negotiation_started = true;
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;

  auto obs = webrtc::make_ref_counted<SyncCreateDesc>();
  webrtc::PeerConnectionInterface::RTCOfferAnswerOptions options;
  pc->CreateAnswer(obs.get(), options);
  if (!obs->Wait(10000)) return HS_STATUS_TIMEOUT;
  if (!obs->ok()) return HS_STATUS_INTERNAL;

  webrtc::SessionDescriptionInterface* desc = obs->TakeDesc();
  if (!desc) return HS_STATUS_INTERNAL;
  // Classic overload takes raw observer + raw desc (ownership transferred).
  auto set_obs = webrtc::make_ref_counted<DummySetLocal>();
  pc->SetLocalDescription(set_obs.get(), desc);

  if (p->closed.load()) return HS_STATUS_STATE;
  std::string sdp = obs->sdp();
  if (sdp.empty() || sdp.size() + 1 > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out_sdp, sdp.c_str(), sdp.size() + 1);
  *out_len = sdp.size();
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_set_local(hs_peer* h, const char* sdp, size_t sdp_len) {
  if (!h || !sdp) return HS_STATUS_NULL;
  (void)sdp_len;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  return HS_STATUS_STATE;
}

HS_API uint32_t hs_peer_set_remote(hs_peer* h, const char* type, size_t type_len,
                            const char* sdp, size_t sdp_len) {
  if (!h || !type || !sdp) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  if (sdp_len == 0 || sdp_len > HS_MAX_SDP_BYTES) return HS_STATUS_BOUNDS;

  std::string t(type, type_len);
  webrtc::SdpType st;
  if (t == "offer") st = webrtc::SdpType::kOffer;
  else if (t == "answer") st = webrtc::SdpType::kAnswer;
  else return HS_STATUS_INVALID;

  webrtc::SdpParseError err;
  auto desc =
      webrtc::CreateSessionDescription(st, std::string(sdp, sdp_len), &err);
  if (!desc) return HS_STATUS_INVALID;

  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return HS_STATUS_STATE;
    p->negotiation_started = true;
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;

  auto obs = webrtc::make_ref_counted<SyncSetDesc>();
  pc->SetRemoteDescription(std::move(desc), obs);
  if (!obs->Wait(10000)) return HS_STATUS_TIMEOUT;
  if (!obs->ok()) return HS_STATUS_INVALID;
  if (p->closed.load()) return HS_STATUS_STATE;

  // Attach DTLS observer for invalidation on failure/cert change.
  auto sctp = pc->GetSctpTransport();
  if (sctp) {
    auto dtls = sctp->dtls_transport();
    if (dtls) {
      std::shared_ptr<DtlsObserver> observer;
      {
        std::lock_guard<std::mutex> lock(p->mu);
        if (p->closed.load()) return HS_STATUS_STATE;
        if (p->dtls) p->dtls->UnregisterObserver();
        observer = std::make_shared<DtlsObserver>(p);
        p->dtls_observer = observer;
        p->dtls = dtls;
        dtls->RegisterObserver(observer.get());
      }
      // Registration does not replay the current state. Snapshot it as well
      // so a transport that connected before observer attachment still binds
      // its authenticated remote certificate.
      observer->OnStateChange(dtls->Information());
    }
  }
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_add_ice(hs_peer* h, const char* sdp, size_t sdp_len) {
  if (!h || !sdp) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  if (sdp_len == 0 || sdp_len > HS_MAX_SDP_BYTES) return HS_STATUS_BOUNDS;

  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return HS_STATUS_STATE;
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;

  webrtc::SdpParseError err;
  std::string line(sdp, sdp_len);
  auto cand = webrtc::IceCandidate::Create("", 0, line, &err);
  if (!cand) cand = webrtc::IceCandidate::Create("0", 0, line, &err);
  if (!cand) return HS_STATUS_INVALID;
  if (!pc->AddIceCandidate(cand.get())) return HS_STATUS_INVALID;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_poll_ice(hs_peer* h, char* out_sdp, size_t cap,
                          size_t* out_len) {
  if (!h || !out_sdp || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (p->local_ice.empty()) {
    return p->ice_overflow ? HS_STATUS_BOUNDS : HS_STATUS_EXHAUSTED;
  }
  // Peek size BEFORE popping; never drop a queued value on capacity failure.
  const std::string& front = p->local_ice.front();
  if (front.size() + 1 > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out_sdp, front.c_str(), front.size() + 1);
  *out_len = front.size();
  p->local_ice_bytes -= front.size();
  p->local_ice.erase(p->local_ice.begin());
  return HS_STATUS_OK;
}

HS_API uint32_t hs_channel_send(hs_peer* h, const uint8_t* data, uint32_t len) {
  if (!h || !data) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  if (len > HS_MAX_MSG_BYTES) return HS_STATUS_BOUNDS;

  // Serialize the authorization check with certificate invalidation so a
  // send cannot race past teardown or pin replacement.
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (p->dtls_failed.load() || !p->HasValidVChanLocked()) {
    return HS_STATUS_HANDSHAKE;
  }
  webrtc::scoped_refptr<webrtc::DataChannelInterface> dc = p->dc;
  if (!dc) return HS_STATUS_STATE;
  if (dc->state() != webrtc::DataChannelInterface::kOpen) return HS_STATUS_STATE;
  webrtc::CopyOnWriteBuffer buf(data, len);
  webrtc::DataBuffer packet(buf, /*binary=*/true);
  if (!dc->Send(packet)) return HS_STATUS_INTERNAL;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_channel_poll(hs_peer* h, uint8_t* out, uint32_t cap,
                         uint32_t* out_len) {
  if (!h || !out || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (p->dtls_failed.load() || !p->HasValidVChanLocked()) {
    return HS_STATUS_HANDSHAKE;
  }
  if (p->inbound_msgs.empty()) {
    return p->inbound_overflow ? HS_STATUS_BOUNDS : HS_STATUS_EXHAUSTED;
  }
  // Peek size BEFORE popping; never drop a queued value on capacity failure.
  const std::string& front = p->inbound_msgs.front();
  if (front.size() > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out, front.data(), front.size());
  *out_len = static_cast<uint32_t>(front.size());
  p->inbound_bytes -= front.size();
  p->inbound_msgs.erase(p->inbound_msgs.begin());
  return HS_STATUS_OK;
}

HS_API uint32_t hs_channel_close(hs_peer* h) {
  if (!h) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
  std::unique_ptr<ChannelObserver> dc_obs;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    dc = p->dc;
    p->dc = nullptr;
    dc_obs = std::move(p->dc_observer);
    p->InvalidateVChanLocked();
  }
  if (dc) {
    dc->UnregisterObserver();
    dc->Close();
  }
  dc_obs.reset();
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_expected_cert_set(hs_peer* h, const char* pem, size_t pem_len) {
  if (!h || !pem) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  if (pem_len == 0 || pem_len > HS_MAX_CERT_PEM_BYTES) return HS_STATUS_BOUNDS;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  // Certificate replacement invalidates every acquired handle.
  p->InvalidateVChanLocked();
  p->expected_cert_pem.assign(pem, pem_len);
  return HS_STATUS_OK;
}

HS_API uint32_t hs_verified_channel_acquire(hs_peer* h, hs_verified_channel** out) {
  if (!h || !out) return HS_STATUS_NULL;
  *out = nullptr;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  if (p->closed.load()) return HS_STATUS_STATE;
  if (p->dtls_failed.load()) return HS_STATUS_HANDSHAKE;

  // Pull the negotiated certificate only from the connected DTLS transport.
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return HS_STATUS_STATE;
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;
  std::string negotiated;
  std::array<uint8_t, kSha256Bytes> remote_fingerprint{};
  if (!ExtractNegotiatedPeerCert(pc.get(), &negotiated, &remote_fingerprint)) {
    return HS_STATUS_HANDSHAKE;
  }

  Token vtok;
  if (!AllocGlobalToken(&vtok)) return HS_STATUS_EXHAUSTED;

  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (p->dtls_failed.load()) return HS_STATUS_HANDSHAKE;
  if (p->expected_cert_pem.empty()) return HS_STATUS_INVALID;
  if (p->expected_cert_pem != negotiated ||
      p->negotiated_cert_pem != negotiated) {
    return HS_STATUS_HANDSHAKE;
  }
  if (!p->certificate || !p->dc ||
      p->dc->state() != webrtc::DataChannelInterface::kOpen ||
      p->dc->label() != kPermittedProductLabel) {
    return HS_STATUS_HANDSHAKE;
  }

  webrtc::Buffer local_digest = webrtc::Buffer::CreateWithCapacity(kSha256Bytes);
  if (!p->certificate->GetSSLCertificate().ComputeDigest("sha-256", local_digest) ||
      local_digest.size() != kSha256Bytes) {
    return HS_STATUS_HANDSHAKE;
  }
  std::array<uint8_t, kSha256Bytes> local_fingerprint{};
  std::copy(local_digest.data(), local_digest.data() + local_digest.size(),
            local_fingerprint.begin());
  hs_webrtc_internal::ChannelBindingBytes channel_binding =
      hs_webrtc_internal::BuildChannelBinding(
          local_fingerprint, remote_fingerprint, p->dc->id());
  if (channel_binding.empty() ||
      channel_binding.size > HS_MAX_CHANNEL_BINDING_BYTES) {
    return HS_STATUS_HANDSHAKE;
  }

  // Replacement invalidates the previous handle (same peer generation).
  p->InvalidateVChanLocked();

  auto vc = std::make_shared<VerifiedChannel>();
  vc->token = vtok;
  vc->engine_token = p->engine_token;
  vc->peer_token = p->token;
  vc->generation = p->generation;
  vc->generation_id = p->generation_id;
  vc->peer_cert_pem = negotiated;
  vc->channel_binding = channel_binding;
  vc->valid.store(true, std::memory_order_release);

  p->vchan = vc;
  {
    std::lock_guard<std::mutex> rlock(g_registry_mu);
    g_vchan_index.emplace(vtok, vc);
  }
  std::shared_ptr<Engine> e = FindEngine(p->engine_token);
  if (e) {
    std::lock_guard<std::mutex> elock(e->mu);
    e->vchans.emplace(vtok, vc);
  }
  *out = reinterpret_cast<hs_verified_channel*>(TokenToHandle(vtok));
  return HS_STATUS_OK;
}

static uint32_t ValidateVerifiedChannelForExportLocked(
    const std::shared_ptr<Peer>& peer,
    const std::shared_ptr<VerifiedChannel>& channel) {
  if (!peer || !channel) return HS_STATUS_NULL;
  if (peer->closed.load()) return HS_STATUS_STATE;
  if (!peer->HasValidVChanLocked() || peer->vchan.get() != channel.get()) {
    return HS_STATUS_STATE;
  }
  if (peer->dtls_failed.load()) {
    return HS_STATUS_HANDSHAKE;
  }
  if (!peer->dtls) {
    return HS_STATUS_HANDSHAKE;
  }
  webrtc::DtlsTransportInformation transport = peer->dtls->Information();
  if (transport.state() != webrtc::DtlsTransportState::kConnected) {
    return HS_STATUS_HANDSHAKE;
  }
  const webrtc::SSLCertChain* chain = transport.remote_ssl_certificates();
  if (!chain || chain->GetSize() == 0 ||
      chain->Get(0).ToPEMString() != channel->peer_cert_pem ||
      peer->expected_cert_pem != channel->peer_cert_pem) {
    return HS_STATUS_HANDSHAKE;
  }
  if (!peer->dc ||
      peer->dc->state() != webrtc::DataChannelInterface::kOpen ||
      peer->dc->label() != kPermittedProductLabel) {
    return HS_STATUS_HANDSHAKE;
  }
  return HS_STATUS_OK;
}

HS_API uint32_t hs_verified_channel_export(hs_verified_channel* v,
                                           uint8_t* out, uint32_t cap,
                                           uint32_t* out_len) {
  if (out_len) *out_len = 0;
  if (!v || !out || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<VerifiedChannel> vc = FindVChanGlobal(HandleToToken(v));
  if (!vc) return HS_STATUS_NULL;
  std::shared_ptr<Peer> peer = FindPeerGlobal(vc->peer_token);
  if (!peer) return HS_STATUS_STATE;
  // Serialize the identity export with pin replacement, channel close, and
  // transport teardown. A validity check alone can race those transitions.
  std::lock_guard<std::mutex> lock(peer->mu);
  uint32_t valid = ValidateVerifiedChannelForExportLocked(peer, vc);
  if (valid != HS_STATUS_OK) return valid;
  if (vc->peer_cert_pem.size() > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out, vc->peer_cert_pem.data(), vc->peer_cert_pem.size());
  *out_len = static_cast<uint32_t>(vc->peer_cert_pem.size());
  return HS_STATUS_OK;
}

HS_API uint32_t hs_verified_channel_binding_export(
    hs_verified_channel* v, uint8_t* out, uint32_t cap, uint32_t* out_len) {
  if (out_len) *out_len = 0;
  if (!v || !out || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<VerifiedChannel> vc = FindVChanGlobal(HandleToToken(v));
  if (!vc) return HS_STATUS_NULL;
  std::shared_ptr<Peer> peer = FindPeerGlobal(vc->peer_token);
  if (!peer) return HS_STATUS_STATE;
  // Keep binding export in the same teardown/repin critical section as the
  // send and poll paths that consume the verified-channel identity.
  std::lock_guard<std::mutex> lock(peer->mu);
  uint32_t valid = ValidateVerifiedChannelForExportLocked(peer, vc);
  if (valid != HS_STATUS_OK) return valid;
  if (vc->channel_binding.empty() ||
      vc->channel_binding.size > HS_MAX_CHANNEL_BINDING_BYTES) {
    return HS_STATUS_STATE;
  }
  if (vc->channel_binding.size > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out, vc->channel_binding.bytes.data(), vc->channel_binding.size);
  *out_len = static_cast<uint32_t>(vc->channel_binding.size);
  return HS_STATUS_OK;
}

HS_API uint32_t hs_verified_channel_generation(hs_verified_channel* v,
                                        uint32_t* out_gen) {
  if (!v || !out_gen) return HS_STATUS_NULL;
  std::shared_ptr<VerifiedChannel> vc = FindVChanGlobal(HandleToToken(v));
  if (!vc) return HS_STATUS_NULL;
  if (!vc->IsValid()) return HS_STATUS_STATE;
  *out_gen = vc->generation;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_verified_channel_valid(hs_verified_channel* v,
                                   uint32_t* out_valid) {
  if (!v || !out_valid) return HS_STATUS_NULL;
  std::shared_ptr<VerifiedChannel> vc = FindVChanGlobal(HandleToToken(v));
  if (!vc) {
    *out_valid = 0;
    return HS_STATUS_STATE;
  }
  *out_valid = vc->IsValid() ? 1u : 0u;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_verified_channel_release(hs_verified_channel* v) {
  if (!v) return HS_STATUS_NULL;
  Token t = HandleToToken(v);
  std::shared_ptr<VerifiedChannel> vc = FindVChanGlobal(t);
  if (!vc) return HS_STATUS_NULL;

  // Serialize release of the current binding with send/poll and peer pin
  // replacement. Old handles are already inactive, so they can be invalidated
  // without touching the active peer slot.
  std::shared_ptr<Peer> p = FindPeerGlobal(vc->peer_token);
  if (p) {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->vchan && p->vchan->token == t) {
      p->InvalidateVChanLocked();
      p->vchan.reset();
    } else {
      vc->Invalidate();
    }
  } else {
    vc->Invalidate();
  }

  // Remove from every owner: global index, engine map, peer slot.
  RetireVChanGlobal(t);
  std::shared_ptr<Engine> e = FindEngine(vc->engine_token);
  if (e) e->RetireVChan(t);
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_drain(hs_peer* h, uint32_t timeout_ms) {
  if (!h) return HS_STATUS_NULL;
  Token t = HandleToToken(h);
  std::shared_ptr<Peer> p = FindPeerGlobal(t);
  if (!p) return HS_STATUS_NULL;

  if (!p->closed.load(std::memory_order_acquire)) {
    hs_peer_close(h);
  }
  // Proven barrier: retire registry entry and report OK. Failed barrier:
  // retain ownership/observers and report TIMEOUT — never dispose on timeout.
  PeerRetire r = RetirePeerFully(p, timeout_ms);
  if (r == PeerRetire::Retained) return HS_STATUS_TIMEOUT;
  return HS_STATUS_OK;
}

// Relay-only TLS/TCP peer through an explicit trusted TURN server.
// Default hs_peer_create keeps existing local behavior. This path offers only
// turns TLS/TCP, requires relay candidate selection (kRelay), and uses exact
// LAB certificate trust. No insecure cert policy option exists.
//
// Exclusive-pin build mode is mandatory. Under ordinary built-in-root mode
// (rtc_builtin_ssl_root_certificates=true) the pinned OpenSSLAdapter skips the
// custom verifier for PKI-valid chains, so a wrong certificate could bypass
// the exact pin. That weaker mode must not silently offer relay trust.
HS_API uint32_t hs_peer_create_relay(hs_engine* h, const hs_turn_tls_config* cfg,
                                 hs_peer** out) {
  if (!h || !out) return HS_STATUS_NULL;
  *out = nullptr;
#if !defined(WEBRTC_EXCLUDE_BUILT_IN_SSL_ROOT_CERTS)
  // Wrong build mode: fail closed. Do not create a weaker pin path.
  (void)cfg;
  return HS_STATUS_UNAVAILABLE;
#else
  std::shared_ptr<Engine> e = FindEngine(HandleToToken(h));
  if (!e || e->shut.load()) return HS_STATUS_NULL;

  // Validate every caller field before creating authority or allocating a peer.
  std::string host, user, pass, trust_pem;
  std::vector<uint8_t> trust_sha;
  uint32_t vst = ValidateTurnConfig(cfg, &host, &user, &pass, &trust_pem,
                                    &trust_sha);
  if (vst != HS_STATUS_OK) return vst;

  Token ptok;
  if (!AllocGlobalToken(&ptok)) return HS_STATUS_EXHAUSTED;

  uint32_t gen;
  uint64_t gen_id;
  {
    std::lock_guard<std::mutex> lock(e->mu);
    if (e->peers.size() >= 64) {
      return HS_STATUS_EXHAUSTED;
    }
    if (e->next_generation == 0 || e->next_generation == UINT32_MAX ||
        e->next_generation_id == 0 || e->next_generation_id == UINT64_MAX) {
      return HS_STATUS_EXHAUSTED;
    }
    gen = e->next_generation++;
    gen_id = e->next_generation_id++;
  }

  auto peer = std::make_shared<Peer>();
  peer->token = ptok;
  peer->engine_token = e->token;
  peer->generation = gen;
  peer->generation_id = gen_id;
  peer->turn_relay_only = true;

  webrtc::KeyParams key_params = webrtc::KeyParams::ECDSA();
  peer->certificate = webrtc::RTCCertificateGenerator::GenerateCertificate(
      key_params, std::nullopt);
  if (!peer->certificate) return HS_STATUS_INTERNAL;

  peer->pc_observer = std::make_unique<PeerObserver>(peer);
  // Shared with the TLS verifier so diagnostics never dangle and remain
  // readable without a selected route.
  peer->turn_trust_diag = std::make_shared<TurnTrustDiagnostics>();
  webrtc::PeerConnectionInterface::RTCConfiguration config;
  config.certificates.push_back(peer->certificate);
  // Relay-only: no host/srflx/prflx fallback. Configuration evidence only;
  // not OS firewall proof.
  config.type = webrtc::PeerConnectionInterface::kRelay;

  webrtc::PeerConnectionInterface::IceServer ice;
  // turns TLS/TCP only. Host is an explicit trusted TURN host (loopback lab).
  ice.urls.push_back("turns:" + host + ":" + std::to_string(cfg->port) +
                     "?transport=tcp");
  // WebRTC requires hostname field only when the URI holds an IP literal
  // (SNI + SSLPostConnectionCheck). A DNS host in the URI carries the name.
  {
    bool host_is_ip = true;
    for (char c : host) {
      if (!(std::isdigit(static_cast<unsigned char>(c)) || c == '.')) {
        host_is_ip = false;
        break;
      }
    }
    if (host_is_ip) {
      ice.hostname = host;
    }
  }
  ice.username = user;
  ice.password = pass;
  ice.tls_cert_policy =
      webrtc::PeerConnectionInterface::kTlsCertPolicySecure;
  config.servers.push_back(ice);

  webrtc::PeerConnectionDependencies deps(peer->pc_observer.get());
  deps.tls_cert_verifier = std::make_unique<HsTurnTlsCertVerifier>(
      trust_pem, std::move(trust_sha), peer->turn_trust_diag);
  auto pc_or = e->factory->CreatePeerConnectionOrError(config, std::move(deps));
  if (!pc_or.ok()) {
    // Honest status only. No raw external error text (can carry paths or
    // host material); callers use return codes and lab diagnostics.
    return HS_STATUS_INTERNAL;
  }
  peer->pc = pc_or.MoveValue();

  {
    std::lock_guard<std::mutex> lock(e->mu);
    e->peers.emplace(ptok, peer);
  }
  {
    std::lock_guard<std::mutex> lock(g_registry_mu);
    g_peer_index.emplace(ptok, peer);
  }
  *out = reinterpret_cast<hs_peer*>(TokenToHandle(ptok));
  return HS_STATUS_OK;
#endif
}

// Actual selected candidate/transport evidence from native stats. Proves both
// peers used relay candidates and TLS/TCP to TURN when those fields are set.
// Offer/answer candidates alone are not selection evidence.
HS_API uint32_t hs_peer_selected_transport_export(hs_peer* h, char* out_json,
                                              size_t cap, size_t* out_len) {
  if (!h || !out_json || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;
  std::string json;
  if (!BuildSelectedTransportJson(pc.get(), &json)) return HS_STATUS_STATE;
  // Lab trust-invocation evidence: the custom verifier must have run. This is
  // not negotiated peer identity and not production trust adoption.
  {
    uint32_t calls = 0;
    uint32_t accepts = 0;
    uint32_t rejects = 0;
    {
      std::lock_guard<std::mutex> lock(p->mu);
      if (p->turn_trust_diag) {
        calls = p->turn_trust_diag->calls.load(std::memory_order_relaxed);
        accepts = p->turn_trust_diag->accepts.load(std::memory_order_relaxed);
        rejects = p->turn_trust_diag->rejects.load(std::memory_order_relaxed);
      }
    }
    std::string extra = ",\"turn_relay_only\":";
    extra += p->turn_relay_only ? "true" : "false";
    extra += ",\"turn_trust_verifier_calls\":";
    extra += std::to_string(calls);
    extra += ",\"turn_trust_verifier_accepts\":";
    extra += std::to_string(accepts);
    extra += ",\"turn_trust_verifier_rejects\":";
    extra += std::to_string(rejects);
    if (!json.empty() && json.back() == '}') {
      json.pop_back();
      json += extra;
      json += "}";
    }
  }
  if (json.size() > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out_json, json.data(), json.size());
  *out_len = json.size();
  return HS_STATUS_OK;
}

// Causal TLS trust diagnostics independent of selected-route existence.
// Reads REAL verifier callback counters. Setup failure / unavailable /
// timeout must not increment these; only Verify/VerifyChain do.
// Not channel identity and not admission.
HS_API uint32_t hs_peer_turn_trust_diagnostics(hs_peer* h, uint32_t* out_calls,
                                               uint32_t* out_accepts,
                                               uint32_t* out_rejects) {
  if (!h || !out_calls || !out_accepts || !out_rejects) return HS_STATUS_NULL;
  *out_calls = 0;
  *out_accepts = 0;
  *out_rejects = 0;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  std::shared_ptr<TurnTrustDiagnostics> diag;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    diag = p->turn_trust_diag;
  }
  if (!diag) return HS_STATUS_STATE;
  *out_calls = diag->calls.load(std::memory_order_relaxed);
  *out_accepts = diag->accepts.load(std::memory_order_relaxed);
  *out_rejects = diag->rejects.load(std::memory_order_relaxed);
  return HS_STATUS_OK;
}

// The host must verify the server-issued observation admission before calling
// this boundary. The bridge then binds that decision to the exact current
// negotiated channel and enforces its monotonic expiry on every media access.
HS_API uint32_t hs_admission_begin(hs_peer* h, const uint8_t* channel_binding,
                                   uint32_t binding_len, uint32_t lease_ms) {
  if (!h || !channel_binding) return HS_STATUS_NULL;
  if (lease_ms == 0 || lease_ms > HS_MAX_OBSERVATION_LEASE_MS ||
      binding_len == 0 || binding_len > HS_MAX_CHANNEL_BINDING_BYTES) {
    return HS_STATUS_BOUNDS;
  }
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (!p->HasValidVChanLocked()) return HS_STATUS_HANDSHAKE;
  const auto& binding = p->vchan->channel_binding;
  if (binding.size != binding_len ||
      !std::equal(binding.bytes.begin(), binding.bytes.begin() + binding.size,
                  channel_binding)) {
    return HS_STATUS_HANDSHAKE;
  }
  if (p->admission_generation == std::numeric_limits<uint64_t>::max()) {
    return HS_STATUS_EXHAUSTED;
  }
  p->ClearMediaAdmissionLocked();
  if (p->admission_generation == std::numeric_limits<uint64_t>::max()) {
    return HS_STATUS_EXHAUSTED;
  }
  ++p->admission_generation;
  p->admission_active = true;
  p->capture_active = false;
  p->admission_channel_token = p->vchan->token;
  p->admission_generation_id = p->vchan->generation_id;
  p->admission_deadline = Clock::now() + std::chrono::milliseconds(lease_ms);
  return HS_STATUS_OK;
}

HS_API uint32_t hs_admission_end(hs_peer* h) {
  if (!h) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  std::lock_guard<std::mutex> lock(p->mu);
  p->ClearMediaAdmissionLocked();
  return HS_STATUS_OK;
}

HS_API uint32_t hs_capture_begin(hs_peer* h, uint32_t expected_generation) {
  if (!h) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load()) return HS_STATUS_STATE;
  if (expected_generation == 0 || expected_generation != p->generation) {
    return HS_STATUS_INVALID;
  }
  if (!p->HasActiveAdmissionLocked(Clock::now())) {
    p->ClearMediaAdmissionLocked();
    return HS_STATUS_HANDSHAKE;
  }
  if (p->video_role != HS_VIDEO_ROLE_SEND_ONLY || !p->desktop_video_source) {
    return HS_STATUS_UNAVAILABLE;
  }
  const uint64_t capture_generation = p->desktop_video_source->Activate();
  if (capture_generation == 0) return HS_STATUS_EXHAUSTED;
  p->capture_active = true;
  p->capture_generation = capture_generation;
  return HS_STATUS_OK;
}

HS_API uint32_t hs_capture_end(hs_peer* h) {
  if (!h) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p) return HS_STATUS_NULL;
  std::lock_guard<std::mutex> lock(p->mu);
  p->capture_active = false;
  p->capture_generation = 0;
  if (p->desktop_video_source) p->desktop_video_source->Deactivate();
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_video_frame_push(hs_peer* h, const uint8_t* bgra,
                                         uint32_t byte_count, uint32_t width,
                                         uint32_t height, uint32_t stride) {
  if (!h || !bgra) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;
  webrtc::scoped_refptr<DesktopVideoSource> source;
  uint64_t capture_generation = 0;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->closed.load()) return HS_STATUS_STATE;
    if (!p->HasActiveAdmissionLocked(Clock::now()) || !p->capture_active) {
      p->ClearMediaAdmissionLocked();
      return HS_STATUS_HANDSHAKE;
    }
    if (p->video_role != HS_VIDEO_ROLE_SEND_ONLY || !p->desktop_video_source) {
      return HS_STATUS_UNAVAILABLE;
    }
    source = p->desktop_video_source;
    capture_generation = p->capture_generation;
  }
  return source->SubmitBgra(
      bgra, byte_count, width, height, stride, capture_generation);
}

HS_API uint32_t hs_media_frame_acquire(hs_peer* h, uint32_t out_cap,
                                       uint8_t* out, uint32_t* out_width,
                                       uint32_t* out_height) {
  if (!h || !out || !out_width || !out_height) return HS_STATUS_NULL;
  *out_width = 0;
  *out_height = 0;
  if (out_cap == 0 || out_cap > HS_MAX_SCREEN_FRAME_BYTES) {
    return HS_STATUS_BOUNDS;
  }
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) {
    hs_webrtc_internal::SecureZero(out, out_cap);
    return HS_STATUS_STATE;
  }
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->closed.load() || !p->HasActiveAdmissionLocked(Clock::now())) {
    p->ClearMediaAdmissionLocked();
    hs_webrtc_internal::SecureZero(out, out_cap);
    return HS_STATUS_HANDSHAKE;
  }
  if (p->remote_video_bgra.empty() || p->remote_video_width == 0 ||
      p->remote_video_height == 0) {
    hs_webrtc_internal::SecureZero(out, out_cap);
    return HS_STATUS_UNAVAILABLE;
  }
  if (p->remote_video_bgra.size() > out_cap ||
      p->remote_video_bgra.size() > HS_MAX_SCREEN_FRAME_BYTES) {
    hs_webrtc_internal::SecureZero(out, out_cap);
    return HS_STATUS_BOUNDS;
  }
  std::memcpy(out, p->remote_video_bgra.data(), p->remote_video_bgra.size());
  *out_width = p->remote_video_width;
  *out_height = p->remote_video_height;
  return HS_STATUS_OK;
}

}  // extern "C"
