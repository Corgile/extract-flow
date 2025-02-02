//
// Created by brian on 2025 Jan 31.
//

#ifndef TYPES_HH
#define TYPES_HH

#include <memory>
#include <pcap/pcap.h>

struct pcap_deleter {
  void operator()(pcap_t* pointer) const;
};
using pcap_handle_t = std::unique_ptr<pcap_t, pcap_deleter>;

#endif //TYPES_HH
