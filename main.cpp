#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#else
#    include <net/if_dl.h>
#endif

#include <array>
#include <chrono>
#include <cstring> // memcpy
#include <optional>
#include <thread>

#include "types.h"

struct addr_pair get_addr_pair(const char* ifname);
int sock_open(const char* dname);
std::optional<std::vector<struct arp>> read_arp_resp(int fd, size_t buflen);

std::optional<struct arp> extract_arp(const struct ether_header* eth) {
    uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != ETH_TYPE_ARP) {
        //printf("Type differs, not an arp packet\n");
        return std::nullopt;
    }

    const uint8_t* payload = (uint8_t*)eth + sizeof(struct ether_header);
    struct arp a;
    a.htype = ntohs(*((const uint16_t*)payload));
    a.ptype = ntohs(*(const uint16_t*)(payload+2));
    a.hlen = *(payload+4);
    a.plen = *(payload+5);
    a.op = ntohs(*((const uint16_t*)(payload+6)));
    memcpy(a.s_ha.data(), payload+8, HALEN);
    memcpy(a.s_pa.data(), payload+14, PALEN);
    memcpy(a.t_ha.data(), payload+18, HALEN);
    memcpy(a.t_pa.data(), payload+24, PALEN);

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
    if (argc != 2) {
        fprintf(stderr, "%s [interface]\n", argv[0]);
        return -1;
    }

    int fd;
    if ((fd = sock_open(argv[1]) ) == -1) {
        return -1;
    }

#ifdef __linux__
    unsigned buf_len = 4096;
#else
    unsigned buf_len;
    if (ioctl(fd, BIOCGBLEN, &buf_len) == -1) {
        perror("ioctl");
        return -1;
    }
#endif

    const struct addr_pair ap = get_addr_pair(argv[1]);
    if (ap.paddrs.empty()) {
        fprintf(stderr, "INET addr not assigned to \"%s\"", argv[1]);
        return -1;
    }

    printf("Host MAC address : %s\n", format_haddr(ap.haddr).data());
    for(addr_mask am : ap.paddrs) {
        printf("[*] Sending an ARP request %s\n", format_paddr(am.addr).data());

        paddr_t netaddr, bcastaddr;
        for(int i = 0; i < PALEN; i++) {
            netaddr[i] = am.addr[i] & am.mask[i];
            bcastaddr[i] = am.addr[i] | (~am.mask[i]);
        }

        for(uint32_t i = htonl(*((uint32_t*)netaddr.data()))+1; i < htonl(*((uint32_t*)bcastaddr.data())); i++) {
            uint32_t addr = ntohl(i);
            paddr_t dst_addr;
            memcpy(dst_addr.data(), &addr, PALEN);
            write(fd, generate_arp_frame(ap.haddr, am.addr, dst_addr).data(), 42);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            auto ret = read_arp_resp(fd, buf_len);
            if (!ret.has_value()) {
                return -1;
            }
            for(arp a : *ret) {
                if (a.t_ha == ap.haddr) {
                    printf("%s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
                }
            }
        }
    }

    puts("[*] ARP requests sent, waiting replies for 10 seconds...");
    auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now() - start < std::chrono::seconds(10)) {
        auto ret = read_arp_resp(fd, buf_len);
        if (!ret.has_value()) {
            return -1;
        }
        for(arp a : *ret) {
            if (a.t_ha == ap.haddr) {
                printf("%s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
            } else {
                printf("Arp response to the other host");
            }
        }
    }

    close(fd);
}
