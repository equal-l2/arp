#include <unistd.h>

#include <chrono> // std::chrono
#include <cstring> // memcpy
#include <optional> // std::optional
#include <cstdio> // printf

#if defined(__linux__)
#   include <netpacket/packet.h> // sockaddr_ll
#   include <net/if.h> // if_nametoindex
#else
#   include <sys/ioctl.h> // ioctl def macro
#   include <net/bpf.h> // ioctl consts for BPF
#endif

#include "types.h"
#include "util.h"

// 一定時間ソケットを読んでARPレスポンスがあれば表示する
int accept_arp_for(unsigned ms, int sockfd, uint8_t* buf, size_t buf_len, ether_addr my_haddr) {
    const auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now()-start < std::chrono::milliseconds(ms)) {
        const auto ret = read_arp_resp(sockfd, buf, buf_len);
        if (!ret.has_value()) {
            return -1;
        }
        for(arp_type a : *ret) {
            if (a.t_ha == my_haddr) {
                printf("%s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
            }/* else {
                printf("Wrong %s : %s\n", format_haddr(a.s_ha).data(), format_paddr(a.s_pa).data());
            }*/
        }
    }
    return 0;
}

#if defined(__linux__)
struct sockaddr_ll configure_sockaddr(const char* ifname, int sockfd, ether_addr haddr) {
    int ifindex;
    if ((ifindex = if_nametoindex(ifname)) == 0) {
        perror("if_nametoindex");
        exit(-1);
    }

    struct sockaddr_ll sendaddr;
    sendaddr.sll_family = AF_PACKET;
    sendaddr.sll_protocol = htons(ETH_P_ARP);
    sendaddr.sll_ifindex = ifindex;
    sendaddr.sll_hatype = 0;
    sendaddr.sll_pkttype = 0;
    sendaddr.sll_halen = ETHER_ADDR_LEN;
    memcpy(sendaddr.sll_addr, OCTET(haddr), ETHER_ADDR_LEN);
    return sendaddr;
}
#endif

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "%s [interface]\n", argv[0]);
        return -1;
    }

    int sockfd;
    if ((sockfd = sock_open(argv[1]) ) == -1) {
        return -1;
    }

#if defined(__linux__)
    unsigned buf_len = 4096;
#else
    // バッファ長取得
    // BPFは指定された長さのバッファを使わなければならない
    unsigned buf_len;
    if (ioctl(sockfd, BIOCGBLEN, &buf_len) == -1) {
        perror("ioctl");
        return -1;
    }
#endif

    // 自身のMACアドレスとIPアドレスを取得する
    const auto ap_opt = get_addr_pair(sockfd, argv[1]);
    if (!ap_opt) {
        fprintf(stderr, "Could not retrive addresses assigned to \"%s\"\n", argv[1]);
        return -1;
    }
    const auto ap = *ap_opt;

    printf("Host MAC address : %s\n", format_haddr(ap.haddr).data());
#if defined(__linux__)
    // sendtoで使うsockaddr構造体を用意する
    const struct sockaddr_ll sendaddr = configure_sockaddr(argv[1], sockfd, ap.haddr);
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

    auto buf = new uint8_t[buf_len];

    for(uint32_t i = begin; i < end; i++) {
        const in_addr addr = {htonl(i)};
        const auto arp_frame = generate_arp_frame(ap.haddr, ap.paddr, addr).data();
#if defined(__linux__)
        const ssize_t ret = sendto(sockfd, arp_frame, 42, 0, (const struct sockaddr*)&sendaddr, sizeof(sendaddr));
#else
        const ssize_t ret = write(sockfd, arp_frame, 42);
#endif
        if (ret == -1) {
            perror("sendto/write");
            return -1;
        }
        accept_arp_for(10, sockfd, buf, buf_len, ap.haddr);
    }

    puts("[*] ARP requests sent, waiting replies for 3 seconds...");
    accept_arp_for(3000, sockfd, buf, buf_len, ap.haddr);
    close(sockfd);
}
