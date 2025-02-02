#include <cmath>
#include <iostream>
#include <map>
#include <numeric>
#include <opencv2/opencv.hpp>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netinet/if_ether.h> // Ethernet header
#include <netinet/ip.h>       // IPv4
#include <netinet/ip6.h>      // IPv6
#include <netinet/tcp.h>

#include <eigen3/unsupported/Eigen/FFT>
#include <fftw3.h>

#include <pcap/pcap.h>

#include <ntv/concurrent_queue.hh>
#include <ntv/raw_packet.hpp>
#include <parallel-hashmap/btree.h>
#define ETHERTYPE_IPV4 ETHERTYPE_IP

using namespace Eigen;

struct SessionKey {
  uint32_t src_ip{};
  uint32_t dst_ip{};
  uint16_t src_port{};
  uint16_t dst_port{};
  uint8_t protocol{}; // Protocol (TCP/UDP)
};

namespace std {
template <>
struct hash<SessionKey> {
  size_t operator()(SessionKey const& key) const noexcept {
    return std::hash<uint32_t>{}(key.src_ip) ^
      std::hash<uint32_t>{}(key.dst_ip) ^ std::hash<uint16_t>{}(key.src_port) ^
      std::hash<uint16_t>{}(key.dst_port) ^ std::hash<uint8_t>{}(key.protocol);
  }
};
} // namespace std

using ustring_t = std::vector<uchar>;
struct Session {
  std::vector<ustring_t> raw_packets_;
  std::vector<pcap_pkthdr> packet_metas_;

  [[nodiscard]] auto flatten() const -> std::vector<char> {
    std::vector<char> data;
    for (auto const& packet : raw_packets_) {
      data.insert(data.end(), packet.begin(), packet.end());
    }
    return data;
  }

  [[nodiscard]] auto stacking() const -> std::vector<uchar> {
    std::vector<uchar> data;
    for (auto const& packet : raw_packets_) {
      data.insert(data.end(), packet.begin(), packet.begin() + 256);
    }
    if (raw_packets_.size() < 256) {
      data.resize(256 * raw_packets_.size(), 0);
    }
    return data;
  }

  [[nodiscard]] auto packet_count() const -> size_t {
    return raw_packets_.size();
  }

  [[nodiscard]] auto byte_count() const -> size_t {
    size_t count{ 0 };
    for (auto const& meta : packet_metas_) { count += meta.caplen; }
    return count;
  }

  [[nodiscard]] auto ith_byte_count(int const idx) const -> int {
    if (idx < 0 or idx >= packet_count()) return 0;
    return int(packet_metas_.at(idx).caplen);
  }

  [[nodiscard]] auto empty() const -> bool { return packet_count() == 0; }

  [[nodiscard]] auto byte_at(int const ith, int const jth) const -> uchar {
    if (ith < 0 or ith >= packet_count()) return 0;
    if (jth < 0 or jth >= ith_byte_count(ith)) return 0;
    return raw_packets_.at(ith).at(jth);
  }

  template <typename DurationUnit>
  [[nodiscard]] auto start_time() const -> long {
    if (empty()) return 0;
    std::chrono::seconds const sec{ packet_metas_.front().ts.tv_sec };
    std::chrono::microseconds const usec{ packet_metas_.front().ts.tv_usec };
    auto const total_duration{ sec + usec };
    return std::chrono::duration_cast<DurationUnit>(total_duration).count();
  }

  template <typename DurationUnit>
  [[nodiscard]] auto end_time() const -> long {
    if (empty()) return 0;
    std::chrono::seconds const sec{ packet_metas_.back().ts.tv_sec };
    std::chrono::microseconds const usec{ packet_metas_.back().ts.tv_usec };
    auto const total_duration{ sec + usec };
    return std::chrono::duration_cast<DurationUnit>(total_duration).count();
  }

  template <typename DurationUnit>
  [[nodiscard]] auto ith_time(int const idx) const -> long {
    if (empty()) return 0;
    std::chrono::seconds const sec{ packet_metas_.at(idx).ts.tv_sec };
    std::chrono::microseconds const usec{ packet_metas_.at(idx).ts.tv_usec };
    auto const total_duration{ sec + usec };
    return std::chrono::duration_cast<DurationUnit>(total_duration).count();
  }
};

using flow_table_t   = phmap::btree_map<SessionKey, Session>;
using packet_queue_t = moodycamel::ConcurrentQueue<raw_packet>;

/**
 * 解析IP地址
 * @param ip_header IP header
 * @return IP address as string
 */
std::string get_ip_str(ip const* ip_header) {
  std::array<char, INET_ADDRSTRLEN> ip_str{};
  inet_ntop(AF_INET, &ip_header->ip_src, ip_str.data(), sizeof(ip_str));
  return { ip_str.data() };
}

/**
 * 解析数据包
 * @param user_data user data
 * @param pkthdr packet header
 * @param packet packet data
 */
void packet_handler(unsigned char* user_data, const pcap_pkthdr* pkthdr,
                    const unsigned char* packet) {
  auto* session = reinterpret_cast<Session*>(user_data);
  // 提取以太网帧头部（Ethernet header）
  auto eth_hdr = (struct ether_header*)packet;

  // 判断是否是 IPv4 数据包
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
    auto ip_hdr =
      (struct ip*)(packet + sizeof(struct ether_header)); // IP header位置
    // 修改源IP和目的IP为全0
    ip_hdr->ip_src.s_addr = inet_addr("0.0.0.0");
    ip_hdr->ip_dst.s_addr = inet_addr("0.0.0.0");
  }
  // 判断是否是 IPv6 数据包
  else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6) {
    auto ip6_hdr =
      (struct ip6_hdr*)(packet +
                        sizeof(struct ether_header)); // IPv6 header位置
    // 修改源和目的IPv6地址为全0
    memset(&ip6_hdr->ip6_src, 0, sizeof(ip6_hdr->ip6_src));
    memset(&ip6_hdr->ip6_dst, 0, sizeof(ip6_hdr->ip6_dst));
  }

  // 将修改后的数据包添加到 session 中
  session->raw_packets_.emplace_back(packet, packet + pkthdr->caplen);
  session->packet_metas_.push_back(*pkthdr);
}

Session load_pcap_session(const std::string& path) {
  using open_offline = pcap_t* (*)(const char*, u_int, char*);
  open_offline const open_func{ pcap_open_offline_with_tstamp_precision };
  std::array<char, PCAP_ERRBUF_SIZE> err_buff{};
  // PCAP_TSTAMP_PRECISION_MICRO, PCAP_TSTAMP_PRECISION_NANO
  auto const handle{ open_func(path.c_str(), 0, err_buff.data()) };
  auto guard{ [](pcap_t* h) { pcap_close(h); } };
  std::unique_ptr<pcap_t, decltype(guard)> handle_ptr{ handle, guard };

  Session session;
  pcap_loop(handle, 256, packet_handler,
            reinterpret_cast<unsigned char*>(&session));
  return session;
}

cv::Mat GAFConvert(std::string_view stream, int w, int h) {
  // 创建一个大小为 h×w 的单通道灰度图像矩阵
  cv::Mat grayImage(h, w, CV_8UC1);
  // 将字节流数据填充到图像矩阵中
  std::memcpy(grayImage.data, stream.data(), stream.size());
  // 将灰度图像转换为浮点型
  grayImage.convertTo(grayImage, CV_32F);
  // 归一化到 [0, 1] 区间
  cv::normalize(grayImage, grayImage, 0, 1, cv::NORM_MINMAX);
  // 创建一个大小为 h×h 的 GAF 矩阵
  cv::Mat gafImage(h, h, CV_32F);
  // 计算 GAF 矩阵
  for (int i = 0; i < h; ++i) {
    for (int j = 0; j < h; ++j) {
      // 计算角度值
      float angle_i = grayImage.at<float>(i);
      float angle_j = grayImage.at<float>(j);
      // 计算 GAF 矩阵元素
      gafImage.at<float>(i, j) = std::cos(angle_i + angle_j);
    }
  }
  // 将 GAF 矩阵转换为灰度图像
  cv::normalize(gafImage, gafImage, 0, 255, cv::NORM_MINMAX);
  gafImage.convertTo(gafImage, CV_8UC1);
  // 返回 GAF 灰度图像
  return gafImage;
}

cv::Mat MTFConvert(std::string_view stream, int w, int h) {
  const int Q = 8; // 分位数数量，可根据需求调整

  // 将字节流转换为double类型的时间序列
  const int N = stream.size();
  std::vector<double> data(N);
  for (int i = 0; i < N; ++i) {
    data[i] = static_cast<unsigned char>(stream[i]);
  }

  // 计算分位数
  std::vector<double> sorted_data(data);
  std::sort(sorted_data.begin(), sorted_data.end());
  std::vector<double> quantiles;
  for (int q = 1; q < Q; ++q) {
    double pos   = (sorted_data.size() - 1) * q / static_cast<double>(Q);
    int idx      = static_cast<int>(pos);
    double frac  = pos - idx;
    double value = sorted_data[idx] * (1 - frac) + sorted_data[idx + 1] * frac;
    quantiles.push_back(value);
  }

  // 符号化数据
  std::vector<int> symbols(N);
  for (int i = 0; i < N; ++i) {
    int s = 0;
    while (s < Q - 1 && data[i] > quantiles[s]) { ++s; }
    symbols[i] = s;
  }

  // 构建转移矩阵
  cv::Mat transition_matrix = cv::Mat::zeros(Q, Q, CV_64F);
  for (int i = 0; i < N - 1; ++i) {
    int from = symbols[i];
    int to   = symbols[i + 1];
    transition_matrix.at<double>(from, to) += 1.0;
  }

  // 归一化转移矩阵
  for (int i = 0; i < Q; ++i) {
    double row_sum = cv::sum(transition_matrix.row(i))[0];
    if (row_sum > 0) { transition_matrix.row(i) /= row_sum; }
  }

  // 构建马尔可夫转移场矩阵
  cv::Mat mtf_matrix(N, N, CV_64F);
  for (int i = 0; i < N; ++i) {
    const int row = symbols[i];
    for (int j = 0; j < N; ++j) {
      const int col               = symbols[j];
      mtf_matrix.at<double>(i, j) = transition_matrix.at<double>(row, col);
    }
  }

  // 归一化并转换为8位灰度图
  cv::Mat normalized;
  cv::normalize(mtf_matrix, normalized, 0, 255, cv::NORM_MINMAX, CV_8UC1);

  // 调整到目标尺寸
  cv::Mat resized;
  cv::resize(normalized, resized, cv::Size(w, h), 0, 0, cv::INTER_NEAREST);

  return resized;
}
// 格拉姆角和场（GASF）
cv::Mat GASFConvert(std::string_view stream, int w, int h) {
  // 将字节流转换为归一化的double序列 [-1, 1]
  const int N = stream.size();
  std::vector<double> data(N);
  for (int i = 0; i < N; ++i) {
    data[i] = static_cast<unsigned char>(stream[i]);
  }

  // 归一化到[-1, 1]
  auto [min_it, max_it] = std::minmax_element(data.begin(), data.end());
  double min_val        = *min_it;
  double max_val        = *max_it;
  std::ranges::transform(data, data.begin(), [=](double x) {
    return 2 * (x - min_val) / (max_val - min_val) - 1;
  });

  // 计算极坐标角度（arccos）
  std::vector<double> angles(N);
  std::ranges::transform(data, angles.begin(),
                 [](double x) { return std::acos(std::clamp(x, -1.0, 1.0)); });

  // 构建GASF矩阵
  cv::Mat gasf(N, N, CV_64F);
  for (int i = 0; i < N; ++i) {
    for (int j = 0; j < N; ++j) {
      gasf.at<double>(i, j) = std::cos(angles[i] + angles[j]);
    }
  }

  // 转换到[0,255]并调整尺寸
  cv::Mat normalized;
  cv::normalize(gasf, normalized, 0, 255, cv::NORM_MINMAX, CV_8UC1);
  cv::Mat resized;
  cv::resize(normalized, resized, cv::Size(w, h), 0, 0, cv::INTER_LINEAR);

  return resized;
}
// 格拉姆角差场（GADF）
cv::Mat GADFConvert(std::string_view stream, int w, int h) {
  // 数据预处理与GASF相同
  const int N = stream.size();
  std::vector<double> data(N);
  for (int i = 0; i < N; ++i) {
    data[i] = static_cast<unsigned char>(stream[i]);
  }

  auto [min_it, max_it] = std::minmax_element(data.begin(), data.end());
  double min_val        = *min_it;
  double max_val        = *max_it;
  std::ranges::transform(data, data.begin(), [=](double x) {
    return 2 * (x - min_val) / (max_val - min_val) - 1;
  });

  // 计算角度
  std::vector<double> angles(N);
  std::ranges::transform(data, angles.begin(),
                 [](double x) { return std::acos(std::clamp(x, -1.0, 1.0)); });

  // 构建GADF矩阵
  cv::Mat gadf(N, N, CV_64F);
  for (int i = 0; i < N; ++i) {
    for (int j = 0; j < N; ++j) {
      gadf.at<double>(i, j) = std::sin(angles[i] - angles[j]); // 注意符号差
    }
  }

  // 转换并调整尺寸
  cv::Mat normalized;
  cv::normalize(gadf, normalized, 0, 255, cv::NORM_MINMAX, CV_8UC1);
  cv::Mat resized;
  cv::resize(normalized, resized, cv::Size(w, h), 0, 0, cv::INTER_LINEAR);

  return resized;
}


// 方法4: 递归图
cv::Mat RP(const Session& session, int width, int height,
           float threshold = 10) {
  std::vector const bytes{ session.flatten() };
  if (bytes.empty()) return {};

  // 降采样
  std::vector<uchar> sampled;
  double const step{ float(bytes.size()) / float(width) };
  for (int i = 0; i < width; ++i) {
    sampled.push_back(bytes[std::min(size_t(i * step), bytes.size() - 1)]);
  }

  cv::Mat rp(width, width, CV_8UC1);
  for (int i = 0; i < width; ++i) {
    for (int j = 0; j < width; ++j) {
      rp.at<uchar>(i, j) =
        int(float(std::abs(sampled[i] - sampled[j])) <= threshold) ? 255 : 0;
    }
  }

  cv::Mat resized;
  cv::resize(rp, resized, cv::Size(width, height), 0, 0, cv::INTER_NEAREST);
  return resized;
}
// 主函数测试
int main() {
  // Session const tcp{ load_pcap_session("/data/Projects/dataset/benign.pcap")
  // };
  Session const tcp{ load_pcap_session(
    "/data/Projects/CPP/pcap2png/pcaps/webshell.pcap") };

  std::vector<char> flatten = tcp.flatten();
  std::string oneDbytes{ flatten.begin(), flatten.end() }; // 模拟字节流
  int width = 256, height = 256;

  cv::Mat result = GAFConvert(oneDbytes, width, height);
  cv::imshow("Gramian Angular Summation Field", result);
  cv::waitKey(0);

  result = MTFConvert(oneDbytes, width, height);
  cv::imshow("Gramian Angular Summation Field", result);
  cv::waitKey(0);

  result = GASFConvert(oneDbytes, width, height);
  cv::imshow("Gramian Angular Summation Field", result);
  cv::waitKey(0);

  result = GADFConvert(oneDbytes, width, height);
  cv::imshow("Gramian Angular Summation Field", result);
  cv::waitKey(0);

  result = RP(tcp, width, height);
  cv::imshow("Gramian Angular Summation Field", result);
  cv::waitKey(0);

  return 0;
}
