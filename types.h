#pragma once

#if defined(__OpenBSD__) || defined(__NetBSD__)
constexpr size_t ETHER_ADDR_LEN = 6;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_IP = 0x0800;
struct ether_addr {
    uint8_t octet[ETHER_ADDR_LEN];
};
#else
#   include <net/ethernet.h>
#endif

#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#ifdef __linux__
#   define OCTET(ethaddr) (ethaddr).ether_addr_octet
#else
#   define OCTET(ethaddr) (ethaddr).octet
#endif

constexpr size_t IP_ADDR_LEN = sizeof(in_addr_t);

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
