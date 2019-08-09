#pragma once
#include "types.h"
#include <array>

int sock_open(const char* dname);
std::array<char, 16> format_paddr(in_addr pa);
std::array<char, 18> format_haddr(ether_addr ha);
std::array<uint8_t, 42> generate_arp_frame(const ether_addr s_ha, const in_addr s_pa, const in_addr t_pa);
std::optional<addrs> get_addr_pair(int sockfd, const char* ifname);
std::optional<std::vector<struct arp_type>> read_arp_resp(int sockfd, uint8_t* buf, size_t buflen);
std::optional<struct arp_type> extract_arp(const struct ether_header* eth);
