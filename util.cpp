// must be included first
#include <sys/types.h>
// or break build on FreeBSD

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if defined(__linux__)
#   include <linux/if_packet.h>
#elif defined(__sun)
#   include <netpacket/packet.h>
#   include <sys/sockio.h>
#else
#   include <fcntl.h>
#   include <net/bpf.h>
#   include <net/if_dl.h>
#endif

#include <cstdio>
#include <cstring>
#include <cerrno>

#include "types.h"
#include "util.h"

// パケットレベルの操作が可能なソケットを開く
int sock_open(const char* ifname) {
#if defined(__linux__) || defined(__sun)
    /* Linux : パケットソケット */
    // RAWレベルのパケットソケットを開く
    const int sockfd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    // ソケットにインタフェースを紐付ける
    const int len = strlen(ifname);
    if (len >= IFNAMSIZ) {
        fprintf(stderr, "setsockopt: ifname is too long\n");
        return -1;
    }

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_ifindex = if_nametoindex(ifname);
    if (bind(sockfd, (const struct sockaddr*)sa, sizeof(sa)) == -1) {
        close(sockfd);
        perror("bind");
        return -1;
    }
#else
    /* BSD : BPF */
    // 空いているBPFデバイスを探す

    char device[sizeof("/dev/bpf0000")];
    int sockfd = -1;
    for (int i = 0; i < 10000; i++) {
        sprintf(device, "/dev/bpf%d", i);
        sockfd = open(device, O_RDWR | O_NONBLOCK);

        if (sockfd == -1 && errno == EBUSY) {
            continue;
        }
        else break;
    }

    if (sockfd == -1) {
        perror("open");
        return -1;
    }
    fprintf(stderr, "Opened BPF device %s\n", device);

    struct ifreq ifr;

    // BPFデバイスにインタフェースを紐づける
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sockfd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl");
        return -1;
    }
#endif
    return sockfd;
}

std::array<char, 16> format_paddr(in_addr pa) {
    std::array<char, 16> ret;
    const auto pa_ptr = (const uint8_t*)&pa.s_addr;
    sprintf(ret.data(), "%d.%d.%d.%d", pa_ptr[0], pa_ptr[1], pa_ptr[2], pa_ptr[3]);
    return ret;
}

std::array<char, 18> format_haddr(ether_addr ha) {
    std::array<char, 18> ret;
    const auto haoct = OCTET(ha);
    sprintf(ret.data(), "%02x:%02x:%02x:%02x:%02x:%02x", haoct[0], haoct[1], haoct[2], haoct[3], haoct[4], haoct[5]);
    return ret;
}

std::array<uint8_t, 42> generate_arp_frame(const ether_addr s_ha, const in_addr s_pa, const in_addr t_pa) {
    std::array<uint8_t, 42> ret;
    uint8_t* data = ret.data();
    const ether_addr t_ha = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* ethernet header */
    // broadcast
    memcpy(data, OCTET(t_ha), ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // own mac address
    memcpy(data, OCTET(s_ha), ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // ethertype
    const uint16_t eth_type = htons(ETHERTYPE_ARP);
    memcpy(data, &eth_type, 2);
    data += 2;

    /* arp */
    // htype = ethernet
    const uint16_t htype = htons(ARPHRD_ETHER);
    memcpy(data, &htype, 2);
    data += 2;

    // ptype = ipv4
    const uint16_t ptype = htons(ETHERTYPE_IP);
    memcpy(data, &ptype, 2);
    data += 2;

    *(data++) = ETHER_ADDR_LEN; // hlen
    *(data++) = IP_ADDR_LEN; // plen

    // op
    const uint16_t op = htons(ARPOP_REQUEST);
    memcpy(data, &op, 2);
    data += 2;

    // s_ha
    memcpy(data, OCTET(s_ha), ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // s_pa
    memcpy(data, &s_pa.s_addr, IP_ADDR_LEN);
    data += IP_ADDR_LEN;

    // t_ha
    memcpy(data, OCTET(t_ha), ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // s_pa
    memcpy(data, &t_pa.s_addr, IP_ADDR_LEN);
    data += IP_ADDR_LEN;

    return ret;
}

std::optional<addrs> get_addr_pair(int sockfd) {
    struct addrs ap {};
    struct ifreq ifr;

#if defined(__linux__) || defined(__sun)
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        return std::nullopt;
    }
    memcpy(OCTET(ap.haddr), ((const struct sockaddr_ll)ifr.ifr_addr).sll_addr, ETHER_ADDR_LEN);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        return std::nullopt;
    }
    ap.paddr = ((const struct sockaddr_in)ifr.ifr_addr).sin_addr;

    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
        perror("ioctl");
        return std::nullopt;
    }
    ap.mask = ((const struct sockaddr_in)ifr.ifr_addr).sin_addr;
#else
    // インタフェース名を取得する
    if (ioctl(sockfd, BIOCGETIF, &ifr) == -1) {
        perror("ioctl");
        return std::nullopt;
    }
    const char* ifname = ifr.ifr_name;

    struct ifaddrs* ifa;
    int ret = getifaddrs(&ifa);
    if(ret == -1) {
        perror("getifaddrs");
        return std::nullopt;
    }

    bool h_found = false, p_found = false;

    for(struct ifaddrs* it = ifa; it != nullptr && !(h_found && p_found); it = it->ifa_next) {
        if (strcmp(ifname, it->ifa_name) == 0) {
            struct sockaddr* sa = it->ifa_addr;
            switch (sa->sa_family) {
                case AF_LINK:
                    {
                        if (!h_found) {
                            const auto a = (const uint8_t*)LLADDR((const struct sockaddr_dl*)sa);
                            memcpy(OCTET(ap.haddr), a, ETHER_ADDR_LEN);
                            h_found = true;
                        }
                        break;
                    }
                case AF_INET:
                    {
                        if (!p_found) {
                            in_addr_t ad = ((const struct sockaddr_in*)sa)->sin_addr.s_addr;
                            in_addr_t nm = ((const struct sockaddr_in*)it->ifa_netmask)->sin_addr.s_addr;
                            ap.paddr.s_addr = ad;
                            ap.mask.s_addr = nm;
                            p_found = true;
                        }
                        break;
                    }
            }
        }
    }

    freeifaddrs(ifa);

    if (!h_found || !p_found) {
        return std::nullopt;
    }
#endif
    return ap;
}

std::optional<std::vector<struct arp>> read_arp_resp(int fd, uint8_t* buf, size_t buflen) {
    std::vector<arp> ret;
#if defined(__linux__) || defined(__sun)
    const ssize_t len = recvfrom(fd, buf, buflen, 0, NULL, NULL);
#else
    const ssize_t len = read(fd, buf, buflen);
#endif
    if(len <= 0) {
        switch (len) {
            case -1:
                {
                    if (errno == EAGAIN) {
                        return std::move(ret);
                    }
                    perror("read");
                    return std::nullopt;
                }
            case 0:
#ifdef __OpenBSD__
                // OpenBSDではnon-blockingなBPFは値がないときに0を返す
                return std::move(ret);
#else
                // 他のプラットフォームでは0が返ってきたら何かおかしい
                fprintf(stderr, "read_arp_resp: socket closed");
                return std::nullopt;
#endif
        }
    }

#if defined(__linux__) || defined(__sun)
    const auto eth = (struct eth_hdr*)buf;
    std::optional<struct arp> a = extract_arp(eth);
    if (a.has_value() && a->op == 2) {
        ret.push_back(*a);
    }
#else
    const uint8_t* packet = buf;
    while(packet - buf < len) {
        const struct bpf_hdr* bpf_header;
        bpf_header = (const struct bpf_hdr*)packet;
        if (bpf_header->bh_caplen >= sizeof(const struct eth_hdr)) {
            const auto eth = (const struct eth_hdr*)(packet + bpf_header->bh_hdrlen);
            std::optional<struct arp> a = extract_arp(eth);
            if (a.has_value() && a->op == 2) {
                ret.push_back(*a);
            }
        }
        packet += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
    }
#endif
    return std::move(ret);
}

std::optional<struct arp> extract_arp(const struct eth_hdr* eth) {
    const uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != ETHERTYPE_ARP) {
        return std::nullopt;
    }

    //printf("Got an arp packet\n");

    const uint8_t* payload = (const uint8_t*)eth + sizeof(struct eth_hdr);
    struct arp a;
    a.htype = ntohs(*((const uint16_t*)payload));
    a.ptype = ntohs(*(const uint16_t*)(payload+2));
    a.hlen = *(payload+4);
    a.plen = *(payload+5);
    a.op = ntohs(*((const uint16_t*)(payload+6)));
    memcpy(OCTET(a.s_ha), payload+8, ETHER_ADDR_LEN);
    memcpy(&a.s_pa.s_addr, payload+14, IP_ADDR_LEN);
    memcpy(OCTET(a.t_ha), payload+18, ETHER_ADDR_LEN);
    memcpy(&a.t_pa.s_addr, payload+24, IP_ADDR_LEN);

    return a;
}
