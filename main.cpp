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
#   include <linux/if_ether.h>
#else
#   include <net/bpf.h>
#endif

#include "types.h"
#include "util.h"

int accept_arp_for(unsigned ms, int fd, size_t buf_len, ether_addr my_haddr) {
    auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now()-start < std::chrono::milliseconds(ms)) {
        auto ret = read_arp_resp(fd, buf_len);
        if (!ret.has_value()) {
            return -1;
        }
        for(arp a : *ret) {
            if (a.t_ha == my_haddr) {
                printf("%s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
            }/* else {
                printf("Wrong %s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
                }*/
        }
    }
    return 0;
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

    auto ap_opt = get_addr_pair(argv[1]);
    if (!ap_opt) {
        fprintf(stderr, "Some addresses are not assigned to \"%s\"", argv[1]);
        return -1;
    }
    auto ap = *ap_opt;

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
    printf("[*] Start sending ARP requests as %s\n", format_paddr(ap.paddr).data());

    const auto paddr = ap.paddr.s_addr;
    const auto mask = ap.mask.s_addr;

    const auto netaddr = paddr & mask;
    const auto bcastaddr = paddr | (~mask);

    const auto begin = ntohl(netaddr)+1;
    const auto end = ntohl(bcastaddr);
    printf(
            "[*] Send to IP between %s and %s (%d host(s))\n",
            format_paddr({htonl(begin)}).data(),
            format_paddr({htonl(end-1)}).data(),
            end-begin
          );
    for(uint32_t i = begin; i < end; i++) {
        const in_addr addr = {htonl(i)};
#ifdef __linux__
        sendto(fd, generate_arp_frame(ap.haddr, ap.paddr, addr).data(), 42, 0, (struct sockaddr*)&sendaddr, sizeof(sendaddr));
#else
        write(fd, generate_arp_frame(ap.haddr, ap.paddr, addr).data(), 42);
#endif
        accept_arp_for(10, fd, buf_len, ap.haddr);
    }

    puts("[*] ARP requests sent, waiting replies for 3 seconds...");
    accept_arp_for(3000, fd, buf_len, ap.haddr);
    close(fd);
}
