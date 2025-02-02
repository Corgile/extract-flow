//
// Created by brian on 11/28/23.
//

#ifndef HOUND_VLAN_HEADER_HPP
#define HOUND_VLAN_HEADER_HPP

#include <cstdint>

namespace hd::type {

struct vlan_header {
  /**
   * @verbatim
   * 0                 1
   * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |Prio |C|         VLAN ID     |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * @endverbatim
   */
  uint16_t vlan;
  /** Ethernet type for next layer */
  uint16_t etherType;
} __attribute__((__packed__));

} // type

#endif //HOUND_VLAN_HEADER_HPP
