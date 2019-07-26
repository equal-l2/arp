#pragma once
#include <array>
#include <cstdint>
#include <vector>

constexpr uint16_t ETH_TYPE_ARP = 0x0806;
constexpr uint8_t HALEN = 6;
constexpr uint8_t PALEN = 4;

using haddr_t = std::array<uint8_t, HALEN>;
using paddr_t = std::array<uint8_t, PALEN>;

struct arp {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    haddr_t s_ha;
    paddr_t s_pa;
    haddr_t t_ha;
    paddr_t t_pa;
};

struct arp_frame {
    uint8_t payload[42];
};

struct addr_mask {
    paddr_t addr;
    paddr_t mask;
};

struct addr_pair {
    haddr_t haddr;
    std::vector<addr_mask> paddrs;
};

