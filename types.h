#pragma once

#ifdef __OpenBSD__
#   include <net/if_arp.h>
#endif

#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#if defined(__sun)
#   define ETHER_ADDR_LEN ETHERADDRL
#endif

#if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__APPLE__)
#   define OCTET(ethaddr) (ethaddr).octet
#else
#   define OCTET(ethaddr) (ethaddr).ether_addr_octet
#endif

#define IP_ADDR_LEN sizeof(in_addr_t)

inline bool operator==(const ether_addr& lhs, const ether_addr& rhs) {
    return std::equal(std::begin(OCTET(lhs)), std::end(OCTET(lhs)), std::begin(OCTET(rhs)));
}

struct eth_hdr {
    uint8_t dhost[ETHER_ADDR_LEN];
    uint8_t shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

struct arp {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    ether_addr s_ha;
    in_addr s_pa;
    ether_addr t_ha;
    in_addr t_pa;
};

struct addrs {
    ether_addr haddr;
    in_addr paddr;
    in_addr mask;
};
