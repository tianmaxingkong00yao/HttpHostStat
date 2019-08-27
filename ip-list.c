#include <WinSock2.h>
#include <ws2tcpip.h>

#include "ip-list.h"
#include "HttpHostStat.h"
#include "util-http.h"

static void
host_list_insert(rbtree_node_t *tmp, rbtree_node_t *node, rbtree_node_t *sentinel);

void HostListInit(HostList *h_tree, hostlist_new_cb new_cb, hostlist_pre_rm_cb rm_cb)
{
	rbtree_init(&h_tree->tree, &h_tree->sentinel, host_list_insert);
	h_tree->new_cb = new_cb;
	h_tree->rm_cb = rm_cb;
}

int HostListAddByFile(HostList *h_tree, int af, const char *addr, const char *domain, const char *location)
{
	HostEntry *host;
	const char *p, *base;

	host = malloc(sizeof(HostEntry));
	if (host == NULL)
		return -1;

	memset(host, 0, sizeof(*host));
	host->ip.family = af;

	if (inet_pton(af, addr, host->ip.addr_data32) != 1) {
		printf("%s address convert failed\n", __FUNCTION__);
		return -1;
	}

	if (location != NULL)
		host->location = _strdup(location);

	if (domain != NULL) {
		
		domain_t *dm;

		base = domain;
		do {
			p = strchr(base, ']');
			if (p == NULL)
				break;

			dm = malloc(sizeof(*dm));
			if (dm == NULL)
				break;

			strncpy_s(dm->name, MAX_PATH, base, p - base);
			dm->next = host->dns_h;
			host->dns_h = dm;
			base = strchr(p, '[');
			if (base != NULL)
				base += 1;
		} while (base != NULL);
	}
		
	h_tree->count += 1;
	host->idx = h_tree->count;
	rbtree_insert(&h_tree->tree, &host->hnode);
	return 0;
}

void HostListUpdate(HostEntry *host, const unsigned char *pkt, unsigned int pktlen)
{
	struct http_message htp_msg;
	char name[MAX_PATH];
	int found = 0;

	if (host == NULL)
		return;

	if (!process_http(&htp_msg, pkt, pktlen)) {
		for (uint8_t i = 0; i < htp_msg.header.num_elements; i++) {
			const struct http_header_element *elem = &htp_msg.header.elements[i];
			if (!_stricmp(elem->name, "Host")) {
				char *p;

				strcpy_s(name, MAX_PATH, elem->value);
				p = strchr(name, ':');
				if (p != NULL) *p = '\0';
				found = 1;

				break;
			}
		}

		http_free_message(&htp_msg);

		if (found != 0) {
			domain_t *dm = host->dns_h;

			while (dm != NULL) {
				if (!_stricmp(dm->name, name))
					break;

				dm = dm->next;
			}

			if (dm == NULL) {
				dm = malloc(sizeof(*dm));
				if (dm != NULL) {
					strcpy_s(dm->name, MAX_PATH, name);
					
					dm->next = host->dns_h;
					host->dns_h = dm;
				}
			}
		}

	}
}

HostEntry *HostListAdd(HostList *h_tree, const Address *addr)
{
	HostEntry *host = NULL;

	host = calloc(1, sizeof(*host));
	if (host == NULL)
		return NULL;

	host->ip.family = addr->family;
	host->ip.addr_data32[0] = addr->addr_data32[0];

	h_tree->count += 1;
	host->idx = h_tree->count;

	rbtree_insert(&h_tree->tree, &host->hnode);

	return host;
}

static int ipaddr_compare(const Address *a, const Address *b)
{
	if (a->family == AF_INET) {
		if (a->addr_data32[0] > b->addr_data32[0])
			return 1;
		else if (a->addr_data32[0] < b->addr_data32[0])
			return -1;
		else
			return 0;
	}
	else {
		return memcmp(a->addr_data32, b->addr_data32, 16);
	}

}

static void
host_list_insert(rbtree_node_t *tmp, rbtree_node_t *node, rbtree_node_t *sentinel)
{
	rbtree_node_t **p;

	while (1) {
		HostEntry *ip1 = CONTAINING_RECORD(node, HostEntry, hnode);
		HostEntry *ip2 = CONTAINING_RECORD(tmp, HostEntry, hnode);
		int cmp = ipaddr_compare(&ip1->ip, &ip2->ip);

		if (cmp < 0) {
			p = &tmp->left;
		}
		else {
			p = &tmp->right;
		}

		if (*p == sentinel) {
			break;
		}

		tmp = *p;
	}

	*p = node;
	node->parent = tmp;
	node->left = sentinel;
	node->right = sentinel;
	node->color = RB_RED;
}

HostEntry *HostListGet(HostList *h_tree, const Address *addr)
{
	rbtree_node_t *node, *sentinel;

	node = h_tree->tree.root;
	sentinel = &h_tree->sentinel;

	while (node != sentinel) {
		HostEntry *host = CONTAINING_RECORD(node, HostEntry, hnode);
		int cmp = ipaddr_compare(addr, &host->ip);

		switch (cmp) {
		case -1:
			node = node->left;
			break;
		case 1:
			node = node->right;
			break;
		default:
			
			return host;
			break;
		}
	}

	return NULL;
}

void HostListDestroy(HostList *h_tree)
{
	rbtree_node_t *node, *root, *sentinel;

	sentinel = &h_tree->sentinel;
	while (1) {
		HostEntry *host;
		domain_t *dm, *next_dm;

		root = h_tree->tree.root;
		if (root == sentinel)
			break;

		node = rbtree_min(root, sentinel);
		rbtree_delete(&h_tree->tree, node);

		host = CONTAINING_RECORD(node, HostEntry, hnode);
		
		if (h_tree->rm_cb)
			h_tree->rm_cb(host);

		if (host->location)
			free(host->location);

		dm = host->dns_h;
		while (dm != NULL) {
			next_dm = dm->next;
			free(dm);
			dm = next_dm;
		}

		free(host);
	}
}
