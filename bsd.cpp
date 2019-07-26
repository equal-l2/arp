#include "types.h"
#ifndef __linux__
struct addr_pair get_addr_pair(const char* ifname) {
    struct ifaddrs* ifa;
    int ret = getifaddrs(&ifa);
    if(ret == -1) {
        perror("getifaddrs");
        exit(1);
    }

    struct addr_pair ap = {{},{}};

    for(struct ifaddrs* it = ifa; it != nullptr; it = it->ifa_next) {
        if (strcmp(ifname, it->ifa_name) == 0) {
            struct sockaddr* sa = it->ifa_addr;
            switch (sa->sa_family) {
                case AF_LINK: 
                    {
                        uint8_t* a = (uint8_t*)LLADDR((struct sockaddr_dl*)sa);
                        memcpy(ap.haddr.data(), a, 6);
                        break;
                    }
                case AF_INET:
                    {
                        uint32_t ad = ((sockaddr_in*)sa)->sin_addr.s_addr;
                        uint32_t nm = ((sockaddr_in*)it->ifa_netmask)->sin_addr.s_addr;
                        paddr_t pa;
                        memcpy(pa.data(), &ad, 4);
                        paddr_t mask;
                        memcpy(mask.data(), &nm, 4);
                        ap.paddrs.push_back({pa, mask});
                        break;
                    }
            }
        }
    }

    freeifaddrs(ifa);

    return ap;
}

int sock_open(const char* dname) {
    char device[sizeof("/dev/bpf0000")];
    int fd = -1;
    for (int i = 0; i < 10000; i++) {
        sprintf(device, "/dev/bpf%d", i);
        fd = open(device, O_RDWR | O_NONBLOCK);

        if (fd == -1 && errno == EBUSY) {
            perror("open");
            continue;
        }
        else break;
    }

    if (fd == -1) {
        perror("open");
        return -1;
    }
    struct ifreq ifr;

    strcpy(ifr.ifr_name, dname); 
    if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl");
        return -1;
    }

    unsigned yes = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &yes) == -1) {
        perror("ioctl");
        return -1;
    }

    return fd;
}

std::optional<std::vector<struct arp>> read_arp_resp(int fd, size_t buflen) {
    char* buf = new char[buflen];
    std::vector<arp> ret;
    ssize_t len = read(fd, buf, buflen);
    if(len <= 0) {
        delete[] buf;
        switch (len) {
            case -1:
                {
                    if (errno == EAGAIN) {
                        return std::move(ret);
                    }
                    perror("read");
                    return std::nullopt;
                }
            case 0:
                fprintf(stderr, "read: socket closed");
                return std::nullopt;
        }
    }

    char* packet = buf;
    while(packet - buf < len) {
        struct bpf_hdr* bpf_header;
        bpf_header = (struct bpf_hdr*)packet;
        if (bpf_header->bh_caplen >= sizeof(struct ether_header)) {
            struct ether_header* eth;
            eth = (struct ether_header*)(packet + bpf_header->bh_hdrlen);
            std::optional<struct arp> a = extract_arp(eth);
            if (a.has_value() && a->op == 2) {
                ret.push_back(*a);
            }
        }
        packet += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
    }
    delete[] buf;
    return std::move(ret);
}
#endif
