#include <arpa/inet.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <array>
#include <vector>

constexpr uint16_t ETH_TYPE_ARP = 0x0806;
constexpr uint8_t HALEN = 6;
constexpr uint8_t PALEN = 4;

using haddr_t = std::array<uint8_t, HALEN>;
using paddr_t = std::array<uint8_t, PALEN>;

struct arp {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    haddr_t s_ha;
    paddr_t s_pa;
    haddr_t t_ha;
    paddr_t t_pa;
};

struct arp_frame {
    uint8_t payload[42];
};

struct arp* extract_arp(const struct ether_header* eth) {
    uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != ETH_TYPE_ARP) {
        //printf("Type differs, not an arp packet\n");
        return nullptr;
    }

    const uint8_t* payload = (uint8_t*)eth + sizeof(struct ether_header);
    struct arp* a = new struct arp;
    a->htype = ntohs(*((const uint16_t*)payload));
    a->ptype = ntohs(*(const uint16_t*)(payload+2));
    a->hlen = *(payload+4);
    a->plen = *(payload+5);
    a->op = ntohs(*((const uint16_t*)(payload+6)));
    memcpy(a->s_ha.data(), payload+8, HALEN);
    memcpy(a->s_pa.data(), payload+14, PALEN);
    memcpy(a->t_ha.data(), payload+18, HALEN);
    memcpy(a->t_pa.data(), payload+24, PALEN);

    return a;
}

std::array<uint8_t, 42> generate_arp_frame(const haddr_t s_ha, const paddr_t s_pa, const paddr_t t_pa) {
    std::array<uint8_t, 42> ret;
    uint8_t* data = ret.data();
    const haddr_t t_ha = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* ethernet header */
    // broadcast
    memcpy(data, t_ha.data(), HALEN);
    data += HALEN;

    // own mac address
    memcpy(data, s_ha.data(), HALEN);
    data += HALEN;

    // ethertype
    const uint16_t eth_type = htons(ETH_TYPE_ARP);
    memcpy(data, &eth_type, 2);
    data += 2;

    /* arp */
    // htype = ethernet
    const uint16_t htype = htons(0x0001);
    memcpy(data, &htype, 2);
    data += 2;

    // ptype = ipv4
    const uint16_t ptype = htons(0x0800);
    memcpy(data, &ptype, 2);
    data += 2;

    *(data++) = HALEN; // hlen
    *(data++) = PALEN; // plen

    // op
    const uint16_t op = htons(0x0001);
    memcpy(data, &op, 2);
    data += 2;

    // s_ha
    memcpy(data, s_ha.data(), HALEN);
    data += HALEN;

    // s_pa
    memcpy(data, s_pa.data(), PALEN);
    data += PALEN;

    // t_ha
    memcpy(data, t_ha.data(), HALEN);
    data += HALEN;

    // s_pa
    memcpy(data, t_pa.data(), PALEN);
    data += PALEN;

    return ret;
}

struct addr_pair {
    haddr_t haddr;
    std::vector<paddr_t> paddrs;
};

struct addr_pair get_addr_pair(const char* ifname) {
    struct ifaddrs* ifa;
    int ret = getifaddrs(&ifa);
    if(ret == -1) {
        perror("getifaddrs");
        exit(1);
    }

    struct addr_pair ap = {{},{}};

    for(struct ifaddrs* it = ifa; it != nullptr; it = it->ifa_next) {
        if (strcmp(ifname, it->ifa_name) == 0) {
            struct sockaddr* sa = it->ifa_addr;
            switch (sa->sa_family) {
                case AF_LINK: 
                    {
                        uint8_t* a = (uint8_t*)LLADDR((struct sockaddr_dl*)sa);
                        memcpy(ap.haddr.data(), a, 6);
                        break;
                    }
                case AF_INET:
                    {
                        uint32_t ad = ((sockaddr_in*)sa)->sin_addr.s_addr;
                        paddr_t pa;
                        memcpy(pa.data(), &ad, 4);
                        ap.paddrs.push_back(pa);
                        break;
                    }
            }
        }
    }

    freeifaddrs(ifa);

    return ap;
}

std::array<char, 16> format_paddr(paddr_t pa) {
    std::array<char, 16> ret;
    sprintf(ret.data(), "%d.%d.%d.%d", pa[0], pa[1], pa[2], pa[3]);
    return ret;
}

std::array<char, 18> format_haddr(haddr_t ha) {
    std::array<char, 18> ret;
    sprintf(ret.data(), "%02x:%02x:%02x:%02x:%02x:%02x", ha[0], ha[1], ha[2], ha[3], ha[4], ha[5]);
    return ret;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "%s [interface] [dst address]\n", argv[0]);
        return -1;
    }

    const in_addr_t iaddr = inet_addr(argv[2]);
    if (iaddr == INADDR_NONE) {
        fprintf(stderr, "Malformed address\n");
        return -1;
    }
    std::array<uint8_t, 4> dst_addr;
    memcpy(dst_addr.data(), &iaddr, 4);

    char device[sizeof("/dev/bpf0000")];
    int fd = -1;
    for (int i = 0; i < 10000; i++) {
        sprintf(device, "/dev/bpf%d", i);
        fd = open(device, O_RDWR);

        if (fd == -1 && errno == EBUSY) {
            perror("open");
            continue;
        }
        else break;
    }

    if (fd == -1) {
        perror("open");
        return -1;
    }
    struct ifreq ifr;

    strcpy(ifr.ifr_name, argv[1]);
    if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl");
        return -1;
    }

    unsigned buf_len = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &buf_len) == -1) {
        perror("ioctl");
        return -1;
    }

    if (ioctl(fd, BIOCGBLEN, &buf_len) == -1) {
        perror("ioctl");
        return -1;
    }

    char* buf = new char[buf_len];

    const struct addr_pair ap = get_addr_pair(argv[1]);
    if (ap.paddrs.empty()) {
        fprintf(stderr, "INET addr not assigned to \"%s\"", argv[1]);
        return -1;
    }

    printf("MAC address : %s\n", format_haddr(ap.haddr).data());
    for(paddr_t addr : ap.paddrs) {
        printf("Send an ARP request to %s as %s\n", format_paddr(dst_addr).data(), format_paddr(addr).data());
        write(fd, generate_arp_frame(ap.haddr, addr, dst_addr).data(), 42);
    }

    printf("Waiting for reply\n");
    while(1) {
        ssize_t len = read(fd, buf, buf_len);
        if(len == -1) {
            perror("read");
            break;
        }
        char* packet = buf;
        while(packet - buf < len) {
            struct bpf_hdr* bpf_header;
            bpf_header = (struct bpf_hdr*)packet;
            if (bpf_header->bh_caplen >= sizeof(struct ether_header)) {
                struct ether_header* eth;
                eth = (struct ether_header*)(packet + bpf_header->bh_hdrlen);
                struct arp* a = extract_arp(eth);
                if (a != nullptr && a->op == 2) {
                    printf("%s : %s\n", format_paddr(a->s_pa).data(), format_haddr(a->s_ha).data());
                }/* else {
                    std::array<uint8_t, 6> haddr;
                    memcpy(haddr.data(), eth->ether_shost, 6);
                    printf("from %s, Not an ARP packet\n", format_haddr(haddr).data());
                }*/
            }
            packet += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
        }
    }
END:

    close(fd);
}
