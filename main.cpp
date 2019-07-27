#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <array>
#include <chrono>
#include <cstring> // memcpy
#include <optional>
#include <thread>

#ifdef __linux__
#   include <linux/if_packet.h>
#else
#   include <net/bpf.h>
#endif

#include "types.h"
#include "common.h"

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
#ifdef __linux__
    struct ifreq ifr;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        return -1;
    }
    struct sockaddr_ll sendaddr;
    sendaddr.sll_family = AF_PACKET;
    sendaddr.sll_protocol = htons(ETH_P_ARP);
    sendaddr.sll_ifindex = ifr.ifr_ifindex;
    sendaddr.sll_hatype = 0;
    sendaddr.sll_pkttype = 0;
    sendaddr.sll_halen = HALEN;
    memcpy(sendaddr.sll_addr, ap.haddr.data(), HALEN);

    struct sockaddr_ll recvaddr = sendaddr;
    recvaddr.sll_pkttype = 0;
    recvaddr.sll_protocol = htons(ETH_P_ARP);

#endif
    for(addr_mask am : ap.paddrs) {
        printf("[*] Sending an ARP request as %s\n", format_paddr(am.addr).data());

        paddr_arr netaddr, bcastaddr;
        for(int i = 0; i < PALEN; i++) {
            netaddr[i] = am.addr[i] & am.mask[i];
            bcastaddr[i] = am.addr[i] | (~am.mask[i]);
        }

        for(uint32_t i = htonl(*((uint32_t*)netaddr.data()))+1; i < htonl(*((uint32_t*)bcastaddr.data())); i++) {
            uint32_t addr = ntohl(i);
            paddr_arr dst_addr;
            memcpy(dst_addr.data(), &addr, PALEN);
#ifdef __linux__
            sendto(fd, generate_arp_frame(ap.haddr, am.addr, dst_addr).data(), 42, 0, (struct sockaddr*)&sendaddr, sizeof(sendaddr));
#else
            write(fd, generate_arp_frame(ap.haddr, am.addr, dst_addr).data(), 42);
#endif
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            auto ret = read_arp_resp(fd, buf_len);
            if (!ret.has_value()) {
                return -1;
            }
            for(arp a : *ret) {
                if (a.t_ha == ap.haddr) {
                    printf("%s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
                } else {
                    printf("Wrong %s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
                }
            }
        }
    }

    puts("[*] ARP requests sent, waiting replies for 5 seconds...");
    auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        auto ret = read_arp_resp(fd, buf_len);
        if (!ret.has_value()) {
            return -1;
        }
        for(arp a : *ret) {
            if (a.t_ha == ap.haddr) {
                printf("%s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
            }  else {
                printf("Wrong %s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
            }
        }
    }

    close(fd);
}
