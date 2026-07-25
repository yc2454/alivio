#ifndef _ALIVIO_STUB_LINUX_IF_ETHER_H
#define _ALIVIO_STUB_LINUX_IF_ETHER_H
#define ETH_HLEN 14
#define ETH_ALEN 6
#define ETH_P_IP      0x0800
#define ETH_P_ARP     0x0806
#define ETH_P_8021Q   0x8100
#define ETH_P_IPV6    0x86DD
#define ETH_P_MPLS_UC 0x8847
#define ETH_P_MPLS_MC 0x8848
#define ETH_P_8021AD  0x88A8
#define ETH_P_ALL     0x0003
#define ETH_P_TEB     0x6558  /* Trans Ether Bridging */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
} __attribute__((packed));
#endif
