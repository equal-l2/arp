#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

constexpr uint16_t ETH_TYPE_ARP = 0x0806;
constexpr uint8_t HALEN = 6;
constexpr uint8_t PALEN = 4;

using haddr_arr = std::array<uint8_t, HALEN>;
using paddr_arr = std::array<uint8_t, PALEN>;

struct arp {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    haddr_arr s_ha;
    paddr_arr s_pa;
    haddr_arr t_ha;
    paddr_arr t_pa;
};

struct arp_frame {
    uint8_t payload[42];
};

struct addr_mask {
    paddr_arr addr;
    paddr_arr mask;
};

struct addr_pair {
    haddr_arr haddr;
    std::vector<addr_mask> paddrs;
};
