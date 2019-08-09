#pragma once

// These should be included at this point with the exact order
#include <sys/socket.h> // required by the other header
#include <netinet/in.h> // in_addr
#include <net/if_arp.h> // required by the other header

#include <netinet/if_ether.h> // ether_addr

#include <algorithm> // std::equal
#include <cstdint> // uint8_t

#if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__APPLE__)
#   define OCTET(ethaddr) (ethaddr).octet
#else
#   define OCTET(ethaddr) (ethaddr).ether_addr_octet
#endif

#define IP_ADDR_LEN sizeof(in_addr_t)

inline bool operator==(const ether_addr& lhs, const ether_addr& rhs) {
    return std::equal(std::begin(OCTET(lhs)), std::end(OCTET(lhs)), std::begin(OCTET(rhs)));
}

struct __attribute__((packed)) arp_type {
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
