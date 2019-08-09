// must be included first
#include <sys/types.h>
// or break build on FreeBSD

#include <net/if.h> // if_nametoindex, ifreq
#include <sys/ioctl.h> // ioctl consts
#include <unistd.h> // close

#if defined(__linux__)
#   include <net/if_packet.h>
#   include <netpacket/packet.h> // sockaddr_ll
#else
#   include <fcntl.h> // open
#   include <ifaddrs.h> // getifaddrs
#   include <net/bpf.h> // ioctl consts for BPF
#   include <net/if_dl.h> // sockaddr_dl
#endif

#include <cstdio> // fprintf, sprintf, perror
#include <cstring> // memset, memcpy
#include <cerrno> // errno

#include "types.h"
#include "util.h"

// パケットレベルの操作が可能なソケットを開く
int sock_open(const char* ifname) {
#if defined(__linux__)
    /* Linux : パケットソケット */
    // RAWレベルのパケットソケットを開く
    const int sockfd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    int ifindex;
    if ((ifindex = if_nametoindex(ifname)) == 0) {
        perror("if_nametoindex");
        return -1;
    }
    sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifindex;
    if (bind(sockfd, (const sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(sockfd);
        return -1;
    }
#else
    /* BSD : BPF */
    // 空いているBPFデバイスを探す

    const int flag = O_RDWR | O_NONBLOCK;
    int sockfd = -1;
    char device[sizeof("/dev/bpf000")];
    sprintf(device, "/dev/bpf");

    // まず /dev/bpf を試す
    if ((sockfd = open(device, flag)) == -1) {
        // なければ /dev/bpf0 ~ /dev/bpf999 を試す
        for (int i = 0; i < 1000; i++) {
            sprintf(device, "/dev/bpf%d", i);
            sockfd = open(device, flag);

            if (sockfd == -1 && errno == EBUSY) continue;
            else break;
        }
    }

    if (sockfd == -1) {
        perror("open");
        return -1;
    }
    fprintf(stderr, "Opened BPF device %s\n", device);

    ifreq ifr;

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
    auto eth = (ether_header*)data;
    auto arp = (arp_type*)(data + sizeof(ether_header));

    /* ethernet header */
    memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN); // set dst to broadcast
    memcpy(eth->ether_shost, OCTET(s_ha), ETHER_ADDR_LEN); // set src to myself
    eth->ether_type = htons(ETHERTYPE_ARP);

    /* arp */
    arp->htype = htons(ARPHRD_ETHER);
    arp->ptype = htons(ETHERTYPE_IP);
    arp->hlen = ETHER_ADDR_LEN;
    arp->plen = IP_ADDR_LEN;
    arp->op = htons(ARPOP_REQUEST);
    arp->s_ha = s_ha;
    arp->s_pa = s_pa;
    arp->t_ha = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    arp->t_pa = t_pa;

    return ret;
}

std::optional<addrs> get_addr_pair(int sockfd, const char* ifname) {
    addrs ap {};

#if defined(__linux__)
    ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        return std::nullopt;
    }
    memcpy(OCTET(ap.haddr), &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        puts("ADDR");
        perror("ioctl");
        return std::nullopt;
    }
    ap.paddr = ((const sockaddr_in*)&ifr.ifr_addr)->sin_addr;

    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
        puts("MASK");
        perror("ioctl");
        return std::nullopt;
    }
    ap.mask = ((const sockaddr_in*)&ifr.ifr_addr)->sin_addr;
#else
    // インタフェース名を取得する
    ifaddrs* ifa;
    int ret = getifaddrs(&ifa);
    if(ret == -1) {
        perror("getifaddrs");
        return std::nullopt;
    }

    bool h_found = false, p_found = false;

    for(ifaddrs* it = ifa; it != nullptr && !(h_found && p_found); it = it->ifa_next) {
        if (strcmp(ifname, it->ifa_name) == 0) {
            sockaddr* sa = it->ifa_addr;
            switch (sa->sa_family) {
                case AF_LINK:
                    {
                        if (!h_found) {
                            const auto a = (const uint8_t*)LLADDR((const sockaddr_dl*)sa);
                            memcpy(OCTET(ap.haddr), a, ETHER_ADDR_LEN);
                            h_found = true;
                        }
                        break;
                    }
                case AF_INET:
                    {
                        if (!p_found) {
                            in_addr_t ad = ((const sockaddr_in*)sa)->sin_addr.s_addr;
                            in_addr_t nm = ((const sockaddr_in*)it->ifa_netmask)->sin_addr.s_addr;
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

std::optional<std::vector<arp_type>> read_arp_resp(int sockfd, uint8_t* buf, size_t buflen) {
    std::vector<arp_type> ret;
#if defined(__linux__)
    const ssize_t len = recvfrom(sockfd, buf, buflen, 0, NULL, NULL);
#else
    const ssize_t len = read(sockfd, buf, buflen);
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

#if defined(__linux__)
    const auto eth = (ether_header*)buf;
    std::optional<arp_type> a = extract_arp(eth);
    if (a.has_value() && ntohs(a->op) == 2) {
        ret.push_back(*a);
    }/* else if (a.has_value()) {
        printf("NOT RESP %d\n", ntohs(a->op));
    }*/
#else
    const uint8_t* packet = buf;
    while(packet - buf < len) {
        const bpf_hdr* bpf_header;
        bpf_header = (const bpf_hdr*)packet;
        if (bpf_header->bh_caplen >= sizeof(const ether_header)) {
            const auto eth = (const ether_header*)(packet + bpf_header->bh_hdrlen);
            std::optional<arp_type> a = extract_arp(eth);
            if (a.has_value() && ntohs(a->op) == 2) {
                ret.push_back(*a);
            }/* else if (a.has_value()) {
                printf("NOT RESP %d\n", ntohs(a->op));
            }*/
        }
        packet += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
    }
#endif
    return std::move(ret);
}

std::optional<arp_type> extract_arp(const ether_header* eth) {
    const uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != ETHERTYPE_ARP) {
        return std::nullopt;
    }

    const uint8_t* payload = (const uint8_t*)eth + sizeof(ether_header);
    arp_type a;
    memcpy(&a, payload, sizeof(arp_type));

    return a;
}
