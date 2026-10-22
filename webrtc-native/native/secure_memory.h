#ifndef HS_WEBRTC_SECURE_MEMORY_H_
#define HS_WEBRTC_SECURE_MEMORY_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hs_webrtc_internal {

// Overwrite a frame buffer through volatile stores so the compiler cannot
// elide the wipe before the allocation is reused or released.
inline void SecureZero(void* memory, std::size_t size) noexcept {
  if (memory == nullptr || size == 0) return;
  auto* bytes = static_cast<volatile std::uint8_t*>(memory);
  for (std::size_t index = 0; index < size; ++index) bytes[index] = 0;
}

inline void SecureZero(std::vector<std::uint8_t>& bytes) noexcept {
  SecureZero(bytes.data(), bytes.size());
}

}  // namespace hs_webrtc_internal

#endif  // HS_WEBRTC_SECURE_MEMORY_H_
