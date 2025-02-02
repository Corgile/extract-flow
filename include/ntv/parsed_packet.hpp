//
// Created by brian on 11/22/23.
//

#ifndef HOUND_PARSED_DATA_HPP
#define HOUND_PARSED_DATA_HPP

#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <ntv/raw_packet.hpp>

#include <ostream>
#include <string>

#define ETHERTYPE_IPV4 ETHERTYPE_IP

namespace hd::type {
struct parsed_packet;

using parsed_vector = std::vector<parsed_packet>;

struct parsed_packet final {

  uint16_t protocol{};
  long mTsSec, mTSuSec, mCapLen;
  std::string mKey, mBlobData;

public:
  parsed_packet() = default;
  [[maybe_unused]]
  parsed_packet(raw_packet const& raw);
  /// @brief c'tor
  parsed_packet(parsed_packet const& copied);
  /// @brief m'tor
  parsed_packet(parsed_packet&& other) noexcept;

  bool present() const;

  friend std::ostream& operator<<(std::ostream& os, parsed_packet const& packet) {
    os
      << "Key: " << packet.mKey
      << ", timestamp: " << packet.mTsSec << "." << packet.mTSuSec
      << ", raw data size: " << packet.mCapLen
      << ", blob data: [ " << packet.mBlobData.size() << " ] bytes";
    return os;
  }

private:
  [[nodiscard("do not discard"), maybe_unused]]
  bool processRawBytes(std::string_view _byteArr);
  [[nodiscard("do not discard"), maybe_unused]]
  bool processIPv4Packet(char const* _ip_bytes);

  template <typename HeaderType>
  void CopyPayloadToBlob(ip const* _ipv4, char const* trans_header,
                         const std::string_view suffix, int const data_offset) {
    auto const* pHeaderType = reinterpret_cast<HeaderType const*>(trans_header);
    auto [_min, _max] = [](HeaderType const* pHeader)-> auto {
      return pHeader->source > pHeader->dest
               ? std::make_pair(ntohs(pHeader->source), ntohs(pHeader->dest))
               : std::make_pair(ntohs(pHeader->dest), ntohs(pHeader->source));
    }(pHeaderType);
    mKey.append(std::to_string(_min)).append("_").append(std::to_string(_max)).append(suffix);
    // payload
    const int available = ntohs(_ipv4->ip_len) - _ipv4->ip_hl * 4 - data_offset;
    size_t const payload_len = std::min(std::max(available, 0), global::opt.payload);
    mBlobData.append(&trans_header[data_offset], payload_len);
    int const padding = global::opt.payload + 128 - mBlobData.size();
    if (padding > 0) [[unlikely]] {
      mBlobData.append(padding, '\0');
    }
  }

private:
  bool HasContent{false};
};
} // hd

#endif //HOUND_PARSED_DATA_HPP
