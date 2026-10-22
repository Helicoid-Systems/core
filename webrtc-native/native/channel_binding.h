#ifndef HS_WEBRTC_CHANNEL_BINDING_H_
#define HS_WEBRTC_CHANNEL_BINDING_H_

#include "hs_webrtc.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace hs_webrtc_internal {

constexpr char kChannelBindingDomain[] = "HS-WEBRTC-DTLS-SCTP-V1";
constexpr char kProductLabel[] = HS_PRODUCT_CHANNEL_LABEL;
constexpr std::size_t kSha256Bytes = 32;
constexpr std::size_t kProductLabelBytes = sizeof(kProductLabel) - 1;
constexpr std::size_t kChannelBindingBytes = sizeof(kChannelBindingDomain) + 2 +
                                             kProductLabelBytes + 2 +
                                             (2 * kSha256Bytes);

static_assert(kProductLabelBytes <= std::numeric_limits<std::uint16_t>::max());
static_assert(kChannelBindingBytes <= HS_MAX_CHANNEL_BINDING_BYTES);

struct ChannelBindingBytes {
  std::array<std::uint8_t, kChannelBindingBytes> bytes{};
  std::size_t size = 0;

  bool empty() const noexcept { return size == 0; }
};

inline ChannelBindingBytes BuildChannelBinding(
    const std::array<std::uint8_t, kSha256Bytes>& local_fingerprint,
    const std::array<std::uint8_t, kSha256Bytes>& remote_fingerprint,
    int stream_id) {
  // RFC 8832 reserves 65535; negotiated SCTP stream IDs are 0 through 65534.
  if (stream_id < 0 ||
      stream_id >= std::numeric_limits<std::uint16_t>::max()) {
    return ChannelBindingBytes{};
  }

  const bool local_is_first = std::lexicographical_compare(
      local_fingerprint.begin(), local_fingerprint.end(),
      remote_fingerprint.begin(), remote_fingerprint.end());
  const auto& first = local_is_first ? local_fingerprint : remote_fingerprint;
  const auto& second = local_is_first ? remote_fingerprint : local_fingerprint;

  ChannelBindingBytes binding;
  auto output = binding.bytes.begin();
  // sizeof includes the domain's required NUL terminator.
  output = std::copy(kChannelBindingDomain,
                     kChannelBindingDomain + sizeof(kChannelBindingDomain),
                     output);
  const auto product_label_bytes =
      static_cast<std::uint16_t>(kProductLabelBytes);
  *output++ = static_cast<std::uint8_t>((product_label_bytes >> 8) & 0xffU);
  *output++ = static_cast<std::uint8_t>(product_label_bytes & 0xffU);
  output = std::copy(kProductLabel,
                     kProductLabel + kProductLabelBytes, output);
  const auto stream = static_cast<std::uint16_t>(stream_id);
  *output++ = static_cast<std::uint8_t>((stream >> 8) & 0xffU);
  *output++ = static_cast<std::uint8_t>(stream & 0xffU);
  output = std::copy(first.begin(), first.end(), output);
  output = std::copy(second.begin(), second.end(), output);
  binding.size = static_cast<std::size_t>(output - binding.bytes.begin());
  return binding;
}

}  // namespace hs_webrtc_internal

#endif  // HS_WEBRTC_CHANNEL_BINDING_H_
