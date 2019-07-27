#ifdef __linux__
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>

#include "types.h"
#include "common.h"
int sock_open(const char* dname) {
    int sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("sock");
        return -1;
    }

    const int len = strlen(dname);
    if (len >= IFNAMSIZ) {
        fprintf(stderr, "setsockopt: ifname is too long\n");
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dname, len) == -1) {
        close(sock);
        perror("setsockopt");
        return -1;
    }

    return sock;
}

std::optional<std::vector<struct arp>> read_arp_resp(int fd, size_t buflen) {
    char* buf = new char[buflen];
    std::vector<arp> ret;
    ssize_t len = recvfrom(fd, buf, buflen, 0, NULL, NULL);
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
                fprintf(stderr, "read: socket closed");
                return std::nullopt;
        }
    }
    //printf("len: %d\n", len);
    auto eth = (struct eth_hdr*)buf;
    std::optional<struct arp> a = extract_arp(eth);
    if (a.has_value() && a->op == 2) {
        ret.push_back(*a);
    }
    delete[] buf;
    return std::move(ret);
}

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
                case AF_PACKET:
                    {
                        uint8_t* a = ((struct sockaddr_ll*)sa)->sll_addr;
                        memcpy(ap.haddr.data(), a, 6);
                        break;
                    }
                case AF_INET:
                    {
                        uint32_t ad = ((sockaddr_in*)sa)->sin_addr.s_addr;
                        uint32_t nm = ((sockaddr_in*)it->ifa_netmask)->sin_addr.s_addr;
                        paddr_arr pa;
                        memcpy(pa.data(), &ad, 4);
                        paddr_arr mask;
                        memcpy(mask.data(), &nm, 4);
                        ap.paddrs.push_back({pa, mask});
                        break;
                    }
            }
        }
    }

    freeifaddrs(ifa);

    return ap;
}
#endif
