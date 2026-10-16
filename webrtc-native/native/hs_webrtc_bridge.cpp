// hs_webrtc_bridge.cpp - Helicoid E01 ABI-3 subset on Google WebRTC.
//
// Explicit engine initialization, owned peer lifecycle, offer/answer + ICE,
// bounded data-channel product messages, channel-evidence from the actual
// negotiated DTLS peer certificate, and honest drain/close.
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
// Capture / admission / media remain explicitly unavailable.

#include "hs_webrtc.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
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
#include "api/environment/environment_factory.h"
#include "api/jsep.h"
#include "api/make_ref_counted.h"
#include "api/peer_connection_interface.h"
#include "api/scoped_refptr.h"
#include "api/sctp_transport_interface.h"
#include "rtc_base/rtc_certificate.h"
#include "rtc_base/rtc_certificate_generator.h"
#include "rtc_base/ssl_adapter.h"
#include "rtc_base/ssl_certificate.h"
#include "rtc_base/ssl_identity.h"
#include "rtc_base/thread.h"


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
  std::atomic<bool> valid{true};

  void Invalidate() { valid.store(false, std::memory_order_release); }
  bool IsValid() const { return valid.load(std::memory_order_acquire); }
};

struct Peer;

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

  std::weak_ptr<Peer> remote;  // in-process harness signaling only

  void InvalidateVChanLocked() {
    if (vchan) vchan->Invalidate();
  }
  void RetireVChanLocked() {
    if (vchan) {
      vchan->Invalidate();
      vchan.reset();
    }
  }
};

void PeerObserver::OnIceConnectionChange(
    webrtc::PeerConnectionInterface::IceConnectionState state) {
  auto p = peer_.lock();
  if (!p) return;
  if (state == webrtc::PeerConnectionInterface::kIceConnectionFailed) {
    p->dtls_failed.store(true, std::memory_order_release);
    p->state.store(HS_PEER_STATE_FAILED, std::memory_order_release);
    std::lock_guard<std::mutex> lock(p->mu);
    p->InvalidateVChanLocked();
  }
}

void PeerObserver::OnConnectionChange(
    webrtc::PeerConnectionInterface::PeerConnectionState state) {
  auto p = peer_.lock();
  if (!p) return;
  using PS = webrtc::PeerConnectionInterface::PeerConnectionState;
  if (state == PS::kConnected) {
    p->state.store(HS_PEER_STATE_CONNECTED, std::memory_order_release);
  } else if (state == PS::kFailed) {
    p->dtls_failed.store(true, std::memory_order_release);
    p->state.store(HS_PEER_STATE_FAILED, std::memory_order_release);
    std::lock_guard<std::mutex> lock(p->mu);
    p->InvalidateVChanLocked();
  } else if (state == PS::kClosed) {
    p->state.store(HS_PEER_STATE_CLOSED, std::memory_order_release);
    std::lock_guard<std::mutex> lock(p->mu);
    p->InvalidateVChanLocked();
  }
}

void PeerObserver::OnIceCandidate(const webrtc::IceCandidate* candidate) {
  auto p = peer_.lock();
  if (!p || !candidate) return;
  std::string sdp = candidate->ToString();
  if (sdp.empty() || sdp.size() > HS_MAX_SDP_BYTES) return;

  std::shared_ptr<Peer> remote_peer;
  {
    std::lock_guard<std::mutex> lock(p->mu);
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
  std::lock_guard<std::mutex> lock(p->mu);
  if (!p->dc) {
    p->dc = channel;
    p->dc_observer = std::make_unique<ChannelObserver>(p);
    channel->RegisterObserver(p->dc_observer.get());
    if (channel->state() == webrtc::DataChannelInterface::kOpen) {
      p->state.store(HS_PEER_STATE_CHANNEL_OPEN, std::memory_order_release);
    }
  } else {
    channel->Close();
  }
}

void ChannelObserver::OnStateChange() {
  auto p = peer_.lock();
  if (!p) return;
  std::lock_guard<std::mutex> lock(p->mu);
  if (p->dc && p->dc->state() == webrtc::DataChannelInterface::kOpen) {
    p->state.store(HS_PEER_STATE_CHANNEL_OPEN, std::memory_order_release);
  }
}

void ChannelObserver::OnMessage(const webrtc::DataBuffer& buffer) {
  auto p = peer_.lock();
  if (!p) return;
  const size_t n = buffer.data.size();
  if (n > HS_MAX_MSG_BYTES) {
    std::lock_guard<std::mutex> lock(p->mu);
    p->inbound_overflow = true;
    return;
  }
  std::lock_guard<std::mutex> lock(p->mu);
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
  if (info.state() == S::kFailed || info.state() == S::kClosed) {
    p->dtls_failed.store(true, std::memory_order_release);
    p->InvalidateVChanLocked();
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
  p->dtls_failed.store(true, std::memory_order_release);
  std::lock_guard<std::mutex> lock(p->mu);
  p->InvalidateVChanLocked();
}

std::string ExtractNegotiatedPeerCertPem(
    webrtc::PeerConnectionInterface* pc) {
  if (!pc) return {};
  auto sctp = pc->GetSctpTransport();
  if (!sctp) return {};
  auto dtls = sctp->dtls_transport();
  if (!dtls) return {};
  webrtc::DtlsTransportInformation info = dtls->Information();
  if (info.state() != webrtc::DtlsTransportState::kConnected) return {};
  const webrtc::SSLCertChain* chain = info.remote_ssl_certificates();
  if (!chain || chain->GetSize() == 0) return {};
  return chain->Get(0).ToPEMString();
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

bool DrainBoth(webrtc::Thread* signaling, webrtc::Thread* network,
               uint32_t timeout_ms) {
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

PeerRetire RetirePeerFully(const std::shared_ptr<Peer>& p, uint32_t timeout_ms,
                           bool require_drain) {
  if (!p) return PeerRetire::Missing;

  if (!p->closed.exchange(true, std::memory_order_acq_rel)) {
    // Close first so no new channel/ICE work is scheduled.
    // Unregister observers BEFORE destroying them so no registered raw
    // callback pointer outlives its observer object.
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
    dc_obs.reset();  // only after UnregisterObserver
    if (pc) {
      std::shared_ptr<Engine> e = FindEngine(p->engine_token);
      webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
      InvokeOnSignaling(sig, [pc]() { pc->Close(); }, 5000);
    }
  }

  std::shared_ptr<Engine> e = FindEngine(p->engine_token);
  webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
  webrtc::Thread* net = e ? e->network_thread.get() : nullptr;

  bool drained_ok = DrainBoth(sig, net, timeout_ms);
  if (!drained_ok && require_drain) {
    // Timeout must not authorize unsafe disposal. Retain exactly once,
    // keyed by token (no duplicate growth).
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
  return HS_STATUS_OK;
}

HS_API uint32_t hs_engine_init(hs_engine** out) {
  if (!out) return HS_STATUS_NULL;
  *out = nullptr;
  if (!webrtc::InitializeSSL()) return HS_STATUS_INTERNAL;

  Token etok;
  if (!AllocGlobalToken(&etok)) {
    webrtc::CleanupSSL();
    return HS_STATUS_EXHAUSTED;
  }

  auto engine = std::make_shared<Engine>();
  engine->token = etok;
  engine->network_thread = webrtc::Thread::CreateWithSocketServer();
  engine->signaling_thread = webrtc::Thread::Create();
  if (!engine->network_thread->Start() || !engine->signaling_thread->Start()) {
    webrtc::CleanupSSL();
    return HS_STATUS_INTERNAL;
  }
  webrtc::EnvironmentFactory env_factory;
  engine->env = env_factory.Create();

  webrtc::PeerConnectionFactoryDependencies deps;
  deps.network_thread = engine->network_thread.get();
  deps.signaling_thread = engine->signaling_thread.get();
  deps.env = *engine->env;
  engine->factory = webrtc::CreateModularPeerConnectionFactory(std::move(deps));
  if (!engine->factory) {
    webrtc::CleanupSSL();
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
  if (p->closed.exchange(true, std::memory_order_acq_rel)) {
    return HS_STATUS_STATE;
  }
  p->state.store(HS_PEER_STATE_CLOSED, std::memory_order_release);
  webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  std::unique_ptr<ChannelObserver> dc_obs;
  {
    std::lock_guard<std::mutex> lock(p->mu);
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
    std::shared_ptr<Engine> e = FindEngine(p->engine_token);
    webrtc::Thread* sig = e ? e->signaling_thread.get() : nullptr;
    InvokeOnSignaling(sig, [pc]() { pc->Close(); }, 5000);
  }
  return HS_STATUS_OK;
}

HS_API uint32_t hs_peer_free(hs_peer* h) {
  if (!h) return HS_STATUS_NULL;
  Token t = HandleToToken(h);
  std::shared_ptr<Peer> p = FindPeerGlobal(t);
  if (!p) return HS_STATUS_NULL;
  if (!p->closed.load(std::memory_order_acquire)) return HS_STATUS_STATE;
  // Free requires a successful drain; timeout retains the object (no UAF).
  PeerRetire r = RetirePeerFully(p, 3000, /*require_drain=*/true);
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

HS_API uint32_t hs_peer_create_offer(hs_peer* h, char* out_sdp, size_t cap,
                              size_t* out_len) {
  if (!h || !out_sdp || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<Peer> p = FindPeerGlobal(HandleToToken(h));
  if (!p || p->closed.load()) return HS_STATUS_STATE;

  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
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
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;

  auto obs = webrtc::make_ref_counted<SyncSetDesc>();
  pc->SetRemoteDescription(std::move(desc), obs);
  if (!obs->Wait(10000)) return HS_STATUS_TIMEOUT;
  if (!obs->ok()) return HS_STATUS_INVALID;

  // Attach DTLS observer for invalidation on failure/cert change.
  auto sctp = pc->GetSctpTransport();
  if (sctp) {
    auto dtls = sctp->dtls_transport();
    if (dtls) {
      std::lock_guard<std::mutex> lock(p->mu);
      if (p->dtls) p->dtls->UnregisterObserver();
      p->dtls_observer = std::make_shared<DtlsObserver>(p);
      p->dtls = dtls;
      dtls->RegisterObserver(p->dtls_observer.get());
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

  webrtc::scoped_refptr<webrtc::DataChannelInterface> dc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    dc = p->dc;
  }
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
  if (p->closed.load() || p->dtls_failed.load()) return HS_STATUS_HANDSHAKE;

  // Pull the negotiated certificate only from the connected DTLS transport.
  webrtc::scoped_refptr<webrtc::PeerConnectionInterface> pc;
  {
    std::lock_guard<std::mutex> lock(p->mu);
    pc = p->pc;
  }
  if (!pc) return HS_STATUS_STATE;
  std::string negotiated = ExtractNegotiatedPeerCertPem(pc.get());
  if (negotiated.empty()) return HS_STATUS_HANDSHAKE;

  Token vtok;
  if (!AllocGlobalToken(&vtok)) return HS_STATUS_EXHAUSTED;

  std::lock_guard<std::mutex> lock(p->mu);
  if (p->dtls_failed.load()) return HS_STATUS_HANDSHAKE;
  if (p->expected_cert_pem.empty()) return HS_STATUS_INVALID;
  if (p->expected_cert_pem != negotiated) return HS_STATUS_HANDSHAKE;

  // Replacement invalidates the previous handle (same peer generation).
  p->InvalidateVChanLocked();

  auto vc = std::make_shared<VerifiedChannel>();
  vc->token = vtok;
  vc->engine_token = p->engine_token;
  vc->peer_token = p->token;
  vc->generation = p->generation;
  vc->generation_id = p->generation_id;
  vc->peer_cert_pem = negotiated;
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

HS_API uint32_t hs_verified_channel_export(hs_verified_channel* v, uint8_t* out,
                                    uint32_t cap, uint32_t* out_len) {
  if (!v || !out || !out_len) return HS_STATUS_NULL;
  std::shared_ptr<VerifiedChannel> vc = FindVChanGlobal(HandleToToken(v));
  if (!vc) return HS_STATUS_NULL;
  if (!vc->IsValid()) return HS_STATUS_STATE;
  if (vc->peer_cert_pem.size() > cap) return HS_STATUS_BOUNDS;
  std::memcpy(out, vc->peer_cert_pem.data(), vc->peer_cert_pem.size());
  *out_len = static_cast<uint32_t>(vc->peer_cert_pem.size());
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
  vc->Invalidate();

  // Remove from every owner: global index, engine map, peer slot.
  RetireVChanGlobal(t);
  std::shared_ptr<Engine> e = FindEngine(vc->engine_token);
  if (e) e->RetireVChan(t);
  std::shared_ptr<Peer> p = FindPeerGlobal(vc->peer_token);
  if (p) {
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->vchan && p->vchan->token == t) {
      p->vchan.reset();
    }
  }
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
  PeerRetire r = RetirePeerFully(p, timeout_ms, /*require_drain=*/false);
  if (r == PeerRetire::Retained) return HS_STATUS_TIMEOUT;
  p->drained.store(true, std::memory_order_release);
  return HS_STATUS_OK;
}

// Explicitly unavailable production surfaces (no stub success).
HS_API uint32_t hs_capture_begin(hs_peer*, uint32_t) { return HS_STATUS_UNAVAILABLE; }
HS_API uint32_t hs_admission_begin(hs_peer*, const char*, size_t) {
  return HS_STATUS_UNAVAILABLE;
}
HS_API uint32_t hs_media_frame_acquire(hs_peer*, uint32_t, uint8_t*, uint32_t*,
                                uint32_t*) {
  return HS_STATUS_UNAVAILABLE;
}

}  // extern "C"
