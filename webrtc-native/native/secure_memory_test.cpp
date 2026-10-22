#include "secure_memory.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
  std::array<std::uint8_t, 4> bytes{1, 2, 3, 4};
  hs_webrtc_internal::SecureZero(bytes.data(), bytes.size());
  assert((bytes == std::array<std::uint8_t, 4>{0, 0, 0, 0}));

  std::vector<std::uint8_t> pixels{4, 3, 2, 1};
  hs_webrtc_internal::SecureZero(pixels);
  assert((pixels == std::vector<std::uint8_t>{0, 0, 0, 0}));

  hs_webrtc_internal::SecureZero(nullptr, 0);
  return 0;
}
