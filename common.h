#pragma once
#include "types.h"

int sock_open(const char* dname);
std::optional<std::vector<struct arp>> read_arp_resp(int fd, size_t buflen);
struct addr_pair get_addr_pair(const char* ifname);

std::array<char, 16> format_paddr(paddr_t pa);
std::array<char, 18> format_haddr(haddr_t ha);
std::array<uint8_t, 42> generate_arp_frame(const haddr_t s_ha, const paddr_t s_pa, const paddr_t t_pa);
std::optional<struct arp> extract_arp(const struct ether_header* eth);
