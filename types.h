#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <vector>
#include <netinet/in.h>
#include <net/ethernet.h>

constexpr size_t IP_ADDR_LEN = sizeof(in_addr_t);

inline bool operator==(const ether_addr& lhs, const ether_addr& rhs) {
    return std::equal(std::begin(lhs.octet), std::end(lhs.octet), std::begin(rhs.octet));
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
