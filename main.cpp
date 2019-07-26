#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring> // memcpy
#include <optional>
#include <thread>

#ifndef __linux__
#   include <sys/ioctl.h>
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
    for(addr_mask am : ap.paddrs) {
        printf("[*] Sending an ARP request as %s\n", format_paddr(am.addr).data());

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
            } else {
                printf("Arp response to the other host");
            }
        }
    }

    close(fd);
}
