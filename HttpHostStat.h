#pragma once

#include <stdint.h>

typedef struct
{
	HostList h_list;
	int link_type;
	int live;
} CaptureContext;

#define ETHERNET_HEADER_LEN 14

#define ETHERNET_TYPE_IP 0x0800
#define ETHERNET_TYPE_ARP 0x0806

#define ETHERNET_TYPE_IPV6 0x86dd

#pragma pack(push, 1)
typedef struct EthernetHdr_ {
	uint8_t eth_dst[6];
	uint8_t eth_src[6];
	uint16_t eth_type;
} EthernetHdr;

typedef struct IPV4Hdr_
{
	uint8_t ip_verhl;     /**< version & header length */
	uint8_t ip_tos;       /**< type of service */
	uint16_t ip_len;      /**< length */
	uint16_t ip_id;       /**< id */
	uint16_t ip_off;      /**< frag offset */
	uint8_t ip_ttl;       /**< time to live */
	uint8_t ip_proto;     /**< protocol (tcp, udp, etc) */
	uint16_t ip_csum;     /**< checksum */
	union {
		struct {
			uint32_t ip_src;/**< source address */
			uint32_t ip_dst;/**< destination address */
		} ip4_un1;
		uint16_t ip_addrs[4];
	} ip4_hdrun1;
} IPV4Hdr;

typedef struct TCPHdr_
{
	uint16_t th_sport;  /**< source port */
	uint16_t th_dport;  /**< destination port */
	uint32_t th_seq;    /**< sequence number */
	uint32_t th_ack;    /**< acknowledgement number */
	uint8_t th_offx2;   /**< offset and reserved */
	uint8_t th_flags;   /**< pkt flags */
	uint16_t th_win;    /**< pkt window */
	uint16_t th_sum;    /**< checksum */
	uint16_t th_urp;    /**< urgent pointer */
} TCPHdr;

#pragma pack(pop)

static _inline uint8_t ip4_get_ver(IPV4Hdr *ip4h)
{
	return ((ip4h->ip_verhl & 0xf0) >> 4);
}

static _inline uint8_t  ip4_get_hdr_len(IPV4Hdr *ip4h)
{
	return ((ip4h->ip_verhl & 0x0f) << 2);
}

static _inline uint16_t ip4_get_ip_len(IPV4Hdr *ip4h)
{
	return ntohs(ip4h->ip_len);
}

static _inline uint8_t tcp_get_hdrlen(TCPHdr *tcph)
{
	return (((tcph->th_offx2 & 0xf0) >> 4) << 2);
}
