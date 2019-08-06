#pragma once
#include "types.h"

int sock_open(const char* dname);
std::array<char, 16> format_paddr(in_addr pa);
std::array<char, 18> format_haddr(ether_addr ha);
std::array<uint8_t, 42> generate_arp_frame(const ether_addr s_ha, const in_addr s_pa, const in_addr t_pa);
std::optional<addrs> get_addr_pair(const char* ifname);
std::optional<std::vector<struct arp>> read_arp_resp(int fd, uint8_t* buf, size_t buflen);
std::optional<struct arp> extract_arp(const struct eth_hdr* eth);
