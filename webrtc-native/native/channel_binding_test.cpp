#include "channel_binding.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
  const std::array<std::uint8_t, hs_webrtc_internal::kSha256Bytes> first{};
  std::array<std::uint8_t, hs_webrtc_internal::kSha256Bytes> low{};
  std::array<std::uint8_t, hs_webrtc_internal::kSha256Bytes> high{};
  low.fill(0x11);
  high.fill(0x22);

  const auto binding =
      hs_webrtc_internal::BuildChannelBinding(high, low, 0x1234);
  std::vector<std::uint8_t> expected;
  constexpr char domain[] = "HS-WEBRTC-DTLS-SCTP-V1";
  expected.insert(expected.end(), domain, domain + sizeof(domain));
  expected.insert(expected.end(), {0x00, 0x0a});
  constexpr char label[] = HS_PRODUCT_CHANNEL_LABEL;
  expected.insert(expected.end(), label, label + sizeof(label) - 1);
  expected.insert(expected.end(), {0x12, 0x34});
  expected.insert(expected.end(), low.begin(), low.end());
  expected.insert(expected.end(), high.begin(), high.end());

  assert(binding.size == expected.size());
  assert(std::equal(expected.begin(), expected.end(), binding.bytes.begin()));
  assert(binding.size == hs_webrtc_internal::kChannelBindingBytes);
  assert(binding.size <= HS_MAX_CHANNEL_BINDING_BYTES);
  const auto reversed =
      hs_webrtc_internal::BuildChannelBinding(low, high, 0x1234);
  assert(reversed.size == binding.size);
  assert(std::equal(binding.bytes.begin(),
                    binding.bytes.begin() + binding.size,
                    reversed.bytes.begin()));
  assert(hs_webrtc_internal::BuildChannelBinding(first, first, 0).size ==
         hs_webrtc_internal::kChannelBindingBytes);
  assert(hs_webrtc_internal::BuildChannelBinding(low, high, -1).empty());
  assert(hs_webrtc_internal::BuildChannelBinding(low, high, 0x10000).empty());
  return 0;
}
