// must be included first
#include <sys/types.h>
// or break build on FreeBSD

#include <arpa/inet.h>

#include <cstdio>
#include <cstring>

#include "types.h"
#include "common.h"

std::array<char, 16> format_paddr(paddr_arr pa) {
    std::array<char, 16> ret;
    sprintf(ret.data(), "%d.%d.%d.%d", pa[0], pa[1], pa[2], pa[3]);
    return ret;
}

std::array<char, 18> format_haddr(haddr_arr ha) {
    std::array<char, 18> ret;
    sprintf(ret.data(), "%02x:%02x:%02x:%02x:%02x:%02x", ha[0], ha[1], ha[2], ha[3], ha[4], ha[5]);
    return ret;
}

std::array<uint8_t, 42> generate_arp_frame(const haddr_arr s_ha, const paddr_arr s_pa, const paddr_arr t_pa) {
    std::array<uint8_t, 42> ret;
    uint8_t* data = ret.data();
    const haddr_arr t_ha = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* ethernet header */
    // broadcast
    memcpy(data, t_ha.data(), HALEN);
    data += HALEN;

    // own mac address
    memcpy(data, s_ha.data(), HALEN);
    data += HALEN;

    // ethertype
    const uint16_t eth_type = htons(ETH_TYPE_ARP);
    memcpy(data, &eth_type, 2);
    data += 2;

    /* arp */
    // htype = ethernet
    const uint16_t htype = htons(0x0001);
    memcpy(data, &htype, 2);
    data += 2;

    // ptype = ipv4
    const uint16_t ptype = htons(0x0800);
    memcpy(data, &ptype, 2);
    data += 2;

    *(data++) = HALEN; // hlen
    *(data++) = PALEN; // plen

    // op
    const uint16_t op = htons(0x0001);
    memcpy(data, &op, 2);
    data += 2;

    // s_ha
    memcpy(data, s_ha.data(), HALEN);
    data += HALEN;

    // s_pa
    memcpy(data, s_pa.data(), PALEN);
    data += PALEN;

    // t_ha
    memcpy(data, t_ha.data(), HALEN);
    data += HALEN;

    // s_pa
    memcpy(data, t_pa.data(), PALEN);
    data += PALEN;

    return ret;
}

std::optional<struct arp> extract_arp(const struct eth_hdr* eth) {
    uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type != ETH_TYPE_ARP) {
        return std::nullopt;
    }

    //printf("Got an arp packet\n");

    const uint8_t* payload = (const uint8_t*)eth + sizeof(struct eth_hdr);
    struct arp a;
    a.htype = ntohs(*((const uint16_t*)payload));
    a.ptype = ntohs(*(const uint16_t*)(payload+2));
    a.hlen = *(payload+4);
    a.plen = *(payload+5);
    a.op = ntohs(*((const uint16_t*)(payload+6)));
    memcpy(a.s_ha.data(), payload+8, HALEN);
    memcpy(a.s_pa.data(), payload+14, PALEN);
    memcpy(a.t_ha.data(), payload+18, HALEN);
    memcpy(a.t_pa.data(), payload+24, PALEN);

    return a;
}

