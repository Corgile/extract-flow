//
// Created by brian on 3/13/24.
//
#include <netinet/udp.h>

#include "ntv/parsed_packet.hpp"
#include "ntv/vlan_header.hpp"

[[maybe_unused]]
hd::type::parsed_packet::parsed_packet(raw_packet const& raw) {
  this->mCapLen = raw.info_hdr.caplen;
  this->mTsSec = raw.info_hdr.ts.tv_sec;
  this->mTSuSec = raw.info_hdr.ts.tv_usec;
  this->HasContent = processRawBytes(raw.byte_arr);
}

bool hd::type::parsed_packet::processRawBytes(std::string_view _byteArr) {
  char const* pointer = _byteArr.data();
  auto eth{reinterpret_cast<ether_header const*>(pointer)};
  if (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
    pointer += static_cast<int>(sizeof(vlan_header));
    eth = reinterpret_cast<ether_header const*>(pointer);
  }
  auto const _ether_type = ntohs(eth->ether_type);
  if (_ether_type not_eq ETHERTYPE_IPV4) {
    return false;
  }
  return processIPv4Packet(pointer + static_cast<int>(sizeof(ether_header)));
}

bool hd::type::parsed_packet::processIPv4Packet(char const* _ip_bytes) {
  auto const _ipv4 = reinterpret_cast<ip const*>(_ip_bytes);
  protocol = static_cast<int>(_ipv4->ip_p);
  if (protocol != IPPROTO_UDP and protocol != IPPROTO_TCP) {
    return false;
  }
  auto [ip1, ip2] = [](ip const* ip_head) -> auto {
    return ip_head->ip_src.s_addr > ip_head->ip_dst.s_addr
           ? std::make_pair(ip_head->ip_dst, ip_head->ip_src)
           : std::make_pair(ip_head->ip_src, ip_head->ip_dst);
  }(_ipv4);
  mKey.append(inet_ntoa(ip1)).append("_").append(inet_ntoa(ip2)).append("_");
  size_t const _ipv4HL = _ipv4->ip_hl * 4;
  mBlobData.append(_ip_bytes, _ipv4HL);
  if (_ipv4HL < 60) [[likely]] {//ip header是变长的，需要补0
    mBlobData.append(60 - _ipv4HL, '\0');
  }
  if (protocol == IPPROTO_TCP) {
    const auto tcph = reinterpret_cast<tcphdr const*>(&_ip_bytes[_ipv4HL]);
    const int tch_header_len = tcph->doff * 4;
    mBlobData.append(&_ip_bytes[_ipv4HL], tch_header_len);
    if (const auto padding = 60 - tch_header_len; padding >= 0) [[likely]] { mBlobData.append(padding, '\0'); }
    mBlobData.append(8, '\0');
    CopyPayloadToBlob<tcphdr>(_ipv4, &_ip_bytes[_ipv4HL], "_TCP", tch_header_len);
  } else if (protocol == IPPROTO_UDP) {
    mBlobData.append(&_ip_bytes[_ipv4HL], 8).append(60, '\0');
    CopyPayloadToBlob<udphdr>(_ipv4, &_ip_bytes[_ipv4HL], "_UDP", 8);
  }
  if (mBlobData.size() not_eq 128 + global::opt.payload) {
    MXLOG_ERROR("Main") << "全部data" << mBlobData.size();//128
  }
  return true;
}

/// @brief c'tor
/// @param copied other instance
hd::type::parsed_packet::parsed_packet(const parsed_packet& copied) {
  mTsSec = copied.mTsSec;
  mTSuSec = copied.mTSuSec;
  mCapLen = copied.mCapLen;
  protocol = copied.protocol;
  mKey = copied.mKey;
  this->mBlobData.assign(copied.mBlobData);
  HasContent = copied.HasContent;
}

hd::type::parsed_packet::parsed_packet(parsed_packet&& other) noexcept {
  mTsSec = other.mTsSec;
  mTSuSec = other.mTSuSec;
  mCapLen = other.mCapLen;
  protocol = other.protocol;
  mKey = std::move(other.mKey);
  mBlobData = std::move(other.mBlobData);
  HasContent = other.HasContent;
}

bool hd::type::parsed_packet::present() const {
  return HasContent;
}
