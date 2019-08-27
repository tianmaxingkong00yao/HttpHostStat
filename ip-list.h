#ifndef _IP_LIST__H
#define _IP_LIST__H

#include <stdint.h>
#include <stdio.h>

#include "rb-tree.h"

#ifdef __cplusplus 
extern "C" {
#endif 

	typedef struct
	{
		char family;
		union {
			uint32_t addr_data32[4];
			uint16_t addr_data16[8];
			uint8_t addr_data8[16];
			struct in6_addr a6;
		};
	} Address;

	typedef struct domain_s
	{
		struct domain_s *next;
		char name[MAX_PATH];
	} domain_t;

	typedef struct
	{
		rbtree_node_t hnode;
		Address ip;
		uint32_t idx;
		
		char *location;
		domain_t *dns_h;
	} HostEntry;

	typedef void(*hostlist_new_cb)(HostEntry *);

	typedef void(*hostlist_pre_rm_cb)(HostEntry *);

	typedef struct
	{
		rbtree_t tree;
		rbtree_node_t sentinel;
		hostlist_new_cb new_cb;
		hostlist_pre_rm_cb rm_cb;
		unsigned int count;
	} HostList;

	void HostListInit(HostList *h_tree, hostlist_new_cb new_cb, hostlist_pre_rm_cb rm_cb);

	int HostListAddByFile(HostList *h_tree, int af, const char *addr, 
		const char *domain, const char *location);

	HostEntry *HostListAdd(HostList *h_tree, const Address *addr);

	HostEntry *HostListGet(HostList *h_tree, const Address *addr);

	void HostListUpdate(HostEntry *host, const unsigned char *pkt, unsigned int pktlen);

	void HostListDestroy(HostList *h_tree);

#ifdef __cplusplus 
}
#endif 

#endif
