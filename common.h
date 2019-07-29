#pragma once
#include "types.h"

int sock_open(const char* dname);
std::optional<std::vector<struct arp>> read_arp_resp(int fd, size_t buflen);
struct addr_pair get_addr_pair(const char* ifname);

paddr_arr ul2paddr(uint32_t paddr);
std::array<char, 16> format_paddr(paddr_arr pa);
std::array<char, 18> format_haddr(haddr_arr ha);
std::array<uint8_t, 42> generate_arp_frame(const haddr_arr s_ha, const paddr_arr s_pa, const paddr_arr t_pa);
std::optional<struct arp> extract_arp(const struct eth_hdr* eth);
uint32_t paddr2ul(paddr_arr paddr);
