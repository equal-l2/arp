// must be included first
#include <sys/types.h>
// or break build on FreeBSD

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <ifaddrs.h>

#ifdef __linux__
#else
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <cerrno>

#include "types.h"
#include "util.h"

int sock_open(const char* dname) {
#ifdef __linux__
    int sockfd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    const int len = strlen(dname);
    if (len >= IFNAMSIZ) {
        fprintf(stderr, "setsockopt: ifname is too long\n");
        return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dname, len) == -1) {
        close(sockfd);
        perror("setsockopt");
        return -1;
    }
#else
    char device[sizeof("/dev/bpf0000")];
    int sockfd = -1;
    for (int i = 0; i < 10000; i++) {
        sprintf(device, "/dev/bpf%d", i);
        sockfd = open(device, O_RDWR | O_NONBLOCK);

        if (sockfd == -1 && errno == EBUSY) {
            perror("open");
            continue;
        }
        else break;
    }

    if (sockfd == -1) {
        perror("open");
        return -1;
    }
    struct ifreq ifr;

    strcpy(ifr.ifr_name, dname); 
    if (ioctl(sockfd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl");
        return -1;
    }

    unsigned yes = 1;
    if (ioctl(sockfd, BIOCIMMEDIATE, &yes) == -1) {
        perror("ioctl");
        return -1;
    }
#endif
    return sockfd;
}

std::array<char, 16> format_paddr(in_addr pa) {
    std::array<char, 16> ret;
    auto pa_ptr = (const uint8_t*)&pa.s_addr;
    sprintf(ret.data(), "%d.%d.%d.%d", pa_ptr[0], pa_ptr[1], pa_ptr[2], pa_ptr[3]);
    return ret;
}

std::array<char, 18> format_haddr(ether_addr ha) {
    std::array<char, 18> ret;
    auto haoct = ha.octet;
    sprintf(ret.data(), "%02x:%02x:%02x:%02x:%02x:%02x", haoct[0], haoct[1], haoct[2], haoct[3], haoct[4], haoct[5]);
    return ret;
}

std::array<uint8_t, 42> generate_arp_frame(const ether_addr s_ha, const in_addr s_pa, const in_addr t_pa) {
    std::array<uint8_t, 42> ret;
    uint8_t* data = ret.data();
    const ether_addr t_ha = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* ethernet header */
    // broadcast
    memcpy(data, t_ha.octet, ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // own mac address
    memcpy(data, s_ha.octet, ETHER_ADDR_LEN);
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
    memcpy(data, s_ha.octet, ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // s_pa
    memcpy(data, &s_pa.s_addr, IP_ADDR_LEN);
    data += IP_ADDR_LEN;

    // t_ha
    memcpy(data, t_ha.octet, ETHER_ADDR_LEN);
    data += ETHER_ADDR_LEN;

    // s_pa
    memcpy(data, &t_pa.s_addr, IP_ADDR_LEN);
    data += IP_ADDR_LEN;

    return ret;
}

std::optional<addrs> get_addr_pair(const char* ifname) {
    struct ifaddrs* ifa;
    int ret = getifaddrs(&ifa);
    if(ret == -1) {
        perror("getifaddrs");
        exit(1);
    }

    struct addrs ap {};
    bool h_found = false, p_found = false;

    for(struct ifaddrs* it = ifa; it != nullptr && !(h_found && p_found); it = it->ifa_next) {
        if (strcmp(ifname, it->ifa_name) == 0) {
            struct sockaddr* sa = it->ifa_addr;
            switch (sa->sa_family) {
                case AF_LINK:
                    {
                        if (!h_found) {
#ifdef __linux__
                            uint8_t* a = ((struct sockaddr_ll*)sa)->sll_addr;
#else
                            uint8_t* a = (uint8_t*)LLADDR((struct sockaddr_dl*)sa);
#endif
                            memcpy(ap.haddr.octet, a, ETHER_ADDR_LEN);
                            h_found = true;
                        }
                        break;
                    }
                case AF_INET:
                    {
                        if (!p_found) {
                            in_addr_t ad = ((sockaddr_in*)sa)->sin_addr.s_addr;
                            in_addr_t nm = ((sockaddr_in*)it->ifa_netmask)->sin_addr.s_addr;
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

    if (h_found && p_found) {
        return ap;
    }
    return std::nullopt;
}

std::optional<std::vector<struct arp>> read_arp_resp(int fd, size_t buflen) {
    char* buf = new char[buflen];
    std::vector<arp> ret;
#ifdef __linux__
    ssize_t len = recvfrom(fd, buf, buflen, 0, NULL, NULL);
#else
    ssize_t len = read(fd, buf, buflen);
#endif
    if(len <= 0) {
        delete[] buf;
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
                fprintf(stderr, "read: socket closed\n");
                return std::nullopt;
        }
    }

#ifdef __linux__
    auto eth = (struct eth_hdr*)buf;
    std::optional<struct arp> a = extract_arp(eth);
    if (a.has_value() && a->op == 2) {
        ret.push_back(*a);
    }
#else
    char* packet = buf;
    while(packet - buf < len) {
        struct bpf_hdr* bpf_header;
        bpf_header = (struct bpf_hdr*)packet;
        if (bpf_header->bh_caplen >= sizeof(struct eth_hdr)) {
            struct eth_hdr* eth;
            eth = (struct eth_hdr*)(packet + bpf_header->bh_hdrlen);
            std::optional<struct arp> a = extract_arp(eth);
            if (a.has_value() && a->op == 2) {
                ret.push_back(*a);
            }
        }
        packet += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
    }
#endif
    delete[] buf;
    return std::move(ret);
}

std::optional<struct arp> extract_arp(const struct eth_hdr* eth) {
    uint16_t eth_type = ntohs(eth->ether_type);

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
    memcpy(a.s_ha.octet, payload+8, ETHER_ADDR_LEN);
    memcpy(&a.s_pa.s_addr, payload+14, IP_ADDR_LEN);
    memcpy(a.t_ha.octet, payload+18, ETHER_ADDR_LEN);
    memcpy(&a.t_pa.s_addr, payload+24, IP_ADDR_LEN);

    return a;
}
