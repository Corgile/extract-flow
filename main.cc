#include <fftw3.h>
#include <iostream>
#include <netinet/if_ether.h> // Ethernet header
#include <netinet/ip.h>       // IPv4
#include <netinet/ip6.h>      // IPv6
#include <numeric>
#include <opencv2/opencv.hpp>
#include <pcap/pcap.h>
#include <vector>

#include <cmath>
#include <map>

using ustring_t = std::vector<uchar>;
struct Session {
  std::vector<ustring_t> raw_packets_;
  std::vector<pcap_pkthdr> packet_metas_;

  [[nodiscard]] auto flatten() const -> std::vector<uchar> {
    std::vector<uchar> data;
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

void packet_handler(unsigned char* user_data, const pcap_pkthdr* pkthdr,
                    const unsigned char* packet) {
  Session* session = reinterpret_cast<Session*>(user_data);
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

// 时域方法：直接绘制数据包字节流
cv::Mat VisualizeTimeDomain(const Session& session, int width, int height) {
  cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
  int packetPos = 0;

  for (const auto& packet : session.raw_packets_) {
    for (int i = 0; i < packet.size() && packetPos < width * height; ++i) {
      int row                     = packetPos / width;
      int col                     = packetPos % width;
      uchar intensity             = packet[i]; // 使用字节作为强度值
      img.at<cv::Vec3b>(row, col) = cv::Vec3b(intensity, intensity, intensity);
      packetPos++;
    }
    if (packetPos >= width * height) break;
  }

  return img;
}

// 频域方法：对字节流进行快速傅里叶变换（FFT）
cv::Mat VisualizeFrequencyDomain(const Session& session, int width,
                                 int height) {
  cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
  int packetPos = 0;

  for (const auto& packet : session.raw_packets_) {
    std::vector<double> realData(packet.begin(),
                                 packet.end()); // 将字节流数据转换为实数序列
    int N = realData.size();

    // 使用FFTW进行傅里叶变换
    fftw_complex* in  = (fftw_complex*)fftw_malloc(sizeof(fftw_complex) * N);
    fftw_complex* out = (fftw_complex*)fftw_malloc(sizeof(fftw_complex) * N);
    fftw_plan p = fftw_plan_dft_1d(N, in, out, FFTW_FORWARD, FFTW_ESTIMATE);

    // 填充输入数据
    for (int i = 0; i < N; ++i) {
      in[i][0] = realData[i]; // 实部
      in[i][1] = 0.0;         // 虚部
    }

    fftw_execute(p); // 执行傅里叶变换

    // 提取频域幅度并归一化
    double maxFreq = 0.0;
    std::vector<double> magnitudes(N);
    for (int i = 0; i < N; ++i) {
      magnitudes[i] =
        sqrt(out[i][0] * out[i][0] + out[i][1] * out[i][1]); // 计算幅度
      maxFreq = std::max(maxFreq, magnitudes[i]);
    }

    // 将频域幅度映射到图像像素
    for (int i = 0; i < N && packetPos < width * height; ++i) {
      int row = packetPos / width;
      int col = packetPos % width;
      uchar intensity =
        static_cast<uchar>(magnitudes[i] / maxFreq * 255); // 归一化
      img.at<cv::Vec3b>(row, col) = cv::Vec3b(intensity, intensity, intensity);
      packetPos++;
    }

    fftw_destroy_plan(p);
    fftw_free(in);
    fftw_free(out);

    if (packetPos >= width * height) break;
  }

  return img;
}

// 递归图法 (VisualRP)
cv::Mat VisualizeRP(const Session& session, int width, int height) {
  cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
  int packetPos = 0;

  // 将字节流展平为一维数组
  std::vector<uchar> data;
  for (const auto& packet : session.raw_packets_) {
    data.insert(data.end(), packet.begin(), packet.end());
  }

  int N = data.size();
  // 计算每对时刻的欧氏距离（相似度）
  for (int i = 0; i < N && packetPos < width * height; ++i) {
    for (int j = 0; j < N && packetPos < width * height; ++j) {
      double distance = std::abs(data[i] - data[j]); // 计算欧氏距离
      uchar intensity = static_cast<uchar>(std::min(distance, 255.0)); // 归一化
      int row         = packetPos / width;
      int col         = packetPos % width;
      img.at<cv::Vec3b>(row, col) = cv::Vec3b(intensity, intensity, intensity);
      packetPos++;
    }
    if (packetPos >= width * height) break;
  }

  return img;
}

// 格拉姆角场 (VisualGAF)
cv::Mat VisualizeGAF(const Session& session, int width, int height) {
  cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
  int packetPos = 0;

  // 将字节流展平为一维数组
  std::vector<uchar> data;
  for (const auto& packet : session.raw_packets_) {
    data.insert(data.end(), packet.begin(), packet.end());
  }

  int N          = data.size();
  double min_val = *std::min_element(data.begin(), data.end());
  double max_val = *std::max_element(data.begin(), data.end());

  // 将字节流标准化到[0, 1]区间
  for (auto& byte : data) {
    byte = static_cast<uchar>((byte - min_val) / (max_val - min_val) * 255);
  }

  // 转化为极坐标并计算GAF
  for (int i = 0; i < N && packetPos < width * height; ++i) {
    double angle  = M_PI * (data[i] / 255.0); // 将字节值映射到[0, π]区间
    double cosine = cos(angle);
    double sine   = sin(angle);

    // 构造GAF矩阵
    for (int j = 0; j < N && packetPos < width * height; ++j) {
      double angle2    = M_PI * (data[j] / 255.0);
      double cosine2   = cos(angle2);
      double sine2     = sin(angle2);
      double gaf_value = cosine * cosine2 + sine * sine2;

      uchar intensity = static_cast<uchar>((gaf_value + 1) * 127.5); // 归一化
      int row         = packetPos / width;
      int col         = packetPos % width;
      img.at<cv::Vec3b>(row, col) = cv::Vec3b(intensity, intensity, intensity);
      packetPos++;
    }
  }

  return img;
}

// 马尔可夫转移场 (VisualMFT)
cv::Mat VisualizeMTF(const Session& session, int width, int height) {
  cv::Mat img = cv::Mat::zeros(height, width, CV_8UC3);

  // 将字节流展平为一维数组
  std::vector<uchar> data;
  for (const auto& packet : session.raw_packets_) {
    data.insert(data.end(), packet.begin(), packet.end());
  }

  int N = data.size();
  std::map<int, int> state_counts;

  // 离散化并统计状态转移频率
  for (int i = 0; i < N - 1; ++i) {
    int state1 = data[i];
    int state2 = data[i + 1];
    state_counts[state1 * 256 + state2]++; // 记录从state1到state2的转移频率
  }

  // 转移矩阵归一化
  double max_val = 0;
  for (const auto& pair : state_counts) {
    max_val = std::max(max_val, (double)pair.second);
  }

  // 映射转移矩阵到图像
  for (const auto& pair : state_counts) {
    int row = pair.first / 256; // 计算行
    int col = pair.first % 256; // 计算列

    // 确保行列索引不超出图像尺寸
    if (row < height && col < width) {
      double intensity = pair.second / max_val * 255.0;
      img.at<cv::Vec3b>(row, col) =
        cv::Vec3b(static_cast<uchar>(intensity), static_cast<uchar>(intensity),
                  static_cast<uchar>(intensity));
    }
  }

  return img;
}

int main() {
  Session const tcp{ load_pcap_session("/data/Projects/CPP/pcap2png/pcaps/webshell.pcap") };
  // Session const tcp{ load_pcap_session("/data/Projects/dataset/benign.pcap") };

  constexpr int width  = 100; // 图像宽度
  constexpr int height = 100; // 图像高度

  cv::Mat img = VisualizeMTF(tcp, width, height);
  cv::imshow("visualizeMTF", img);
  cv::waitKey(0);

  img = VisualizeRP(tcp, width, height);
  cv::imshow("visualizeRP", img);
  cv::waitKey(0);

  img = VisualizeGAF(tcp, width, height);
  cv::imshow("visualizeGAF", img);
  cv::waitKey(0);

  img = VisualizeTimeDomain(tcp, width, height);
  cv::imshow("VisualizeTimeDomain", img);
  cv::waitKey(0);

  img = VisualizeFrequencyDomain(tcp, width, height);
  cv::imshow("VisualizeFrequencyDomain", img);
  cv::waitKey(0);
  return 0;
}
