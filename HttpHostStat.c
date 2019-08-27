#include <winsock2.h>
#include <WinDNS.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <strsafe.h>

#include "ip-list.h"
#include "HttpHostStat.h"
#include "qqwry.h"

CaptureContext gPcapCtx;
FILE *gHostFilePointer = NULL;
char gPath[MAX_PATH];

void Usage(void)
{
	printf("-r <file name>\n -i <interface>\n");
	exit(EXIT_FAILURE);
}

int load_host_file(const char *filename)
{
	char *buf = NULL;
	char *location = NULL;
	FILE *fp = NULL;
	int bufz = 4096;
	int locz = 512;

	if (fopen_s(&fp, filename, "a+"))
		return -1;

	buf = (char *)malloc(bufz) ;
	if (buf == NULL) {
		fclose(fp);
		
		return -1;
	}

	location = (char *)malloc(locz);
	if (location == NULL) {
		fclose(fp);
		free(buf);

		return -1;
	}

	while (fgets(buf, bufz - 1, fp)) {
		
		char addr[64] = { 0 };
		char *p = NULL;
		int i;

		if (!*buf || *buf == '\r' || *buf == '\n')
			continue;

		p = strchr(buf, '\n');
		if (p != NULL) *p = '\0';

		p = strchr(buf, ' ');
		if (p == NULL)
			continue;

		i = p - buf;
		i = i < sizeof(addr) ? i : sizeof(addr) - 1;
		strncpy_s(addr, sizeof(addr), buf, i);

		memset(location, 0, locz);

		p = strchr(buf, '<');
		if (p != NULL) {
			i = 0;
			p++;
			while ((*p != '>') && (i < locz - 1)) {
				location[i++] = *p;
				++p;
			}
		}
		else {
			
			continue;
		}

		p = strchr(p, '[');
		if (p != NULL) {
			p += 1;
			
		}
		else {
			continue;
		}

		if (0 != HostListAddByFile(&gPcapCtx.h_list, AF_INET, addr, p, location))
			break;
	}
	
	printf("Load %d items\n", gPcapCtx.h_list.count);
	free(location);
	free(buf);
	fclose(fp);
	
	return 0;
}

char *ip4_to_string(unsigned char *ip, char *szAddr, unsigned int cchAddr)
{
	int n;

	n = snprintf(szAddr, cchAddr, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	szAddr[n] = '\0';
	return szAddr;
}

void decode_ip4(CaptureContext *ctx, const u_char *pkt, unsigned int pktlen)
{
	IPV4Hdr *hdr = (IPV4Hdr *)pkt;
	TCPHdr *tcph;
	unsigned int plen;
	Address addr;
	HostEntry *host;

	if (ip4_get_ver(hdr) != 4)
		return;

	plen = ip4_get_hdr_len(hdr);
	if (plen > pktlen)
		return;

	if (hdr->ip_proto != IPPROTO_TCP)
		return;

	pkt += plen;
	pktlen -= plen;
	tcph = (TCPHdr *)pkt;
	
	plen = tcp_get_hdrlen(tcph);
	if (plen > pktlen)
		return;

	if (ntohs(tcph->th_dport) != 80)
		return;

	addr.family = AF_INET;

	addr.addr_data32[0] = hdr->ip4_hdrun1.ip4_un1.ip_dst;
	if (!(host = HostListGet(&ctx->h_list, &addr))) {
		
		host = HostListAdd(&ctx->h_list, &addr);
	}
	
	pkt += plen;
	pktlen -= plen;
	HostListUpdate(host, pkt, pktlen);
}

void decode_ethernet(CaptureContext *ctx, const u_char *pkt, unsigned int pktlen)
{
	EthernetHdr *eth = (EthernetHdr *)pkt;

	if (pktlen < sizeof(EthernetHdr))
		return;

	if (ntohs(eth->eth_type) != ETHERNET_TYPE_IP)
		return;

	decode_ip4(ctx, pkt + sizeof(EthernetHdr), pktlen - sizeof(EthernetHdr));
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	CaptureContext *ctx = (CaptureContext *)arg;

	switch (ctx->link_type) {
	case DLT_EN10MB:
		decode_ethernet(ctx, pkt_data, header->caplen);
		break;
	case DLT_RAW:
		decode_ip4(ctx, pkt_data, header->caplen);
		break;
	default:
		break;
	}
}

void get_host_info(HostEntry *host)
{
	char buf[256];
	PDNS_RECORD record = NULL;
	BOOLEAN completed = FALSE;

	if (!host->dns_h) {
		sprintf_s(buf, 256, "%hhu.%hhu.%hhu.%hhu.%s",
			host->ip.addr_data8[3],
			host->ip.addr_data8[2],
			host->ip.addr_data8[1],
			host->ip.addr_data8[0],
			DNS_IP4_REVERSE_DOMAIN_STRING_A);

		DnsQuery_A(buf, DNS_TYPE_PTR, 0,
			NULL, &record, NULL);
		if (record != NULL) {
			domain_t *dm = (domain_t *)malloc(sizeof(*dm));

			if (dm != NULL) {
				strcpy_s(dm->name, MAX_PATH, record->Data.PTR.pNameHost);
				dm->next = host->dns_h;
				host->dns_h = dm;
			}
			
			DnsRecordListFree(record, DnsFreeRecordList);
		}

	}
	
}

void dump_host_info(HostEntry *host)
{
	char ip_str[INET_ADDRSTRLEN];
	char location[256];

	if (gHostFilePointer == NULL)
		return;

	if (host->dns_h == NULL)
		return;

	ip4_to_string(host->ip.addr_data8, ip_str, sizeof(ip_str));

	fprintf(gHostFilePointer, "%s ", ip_str);
	if (!qqwrydb_get_ipv4_geo_info(ip_str, location, 256)) {
		fprintf(gHostFilePointer, "<Unknown>");
	}
	else {
		fprintf(gHostFilePointer, "<%s>", location);
	}

	domain_t *dm = host->dns_h;
	while (dm != NULL) {
		fprintf(gHostFilePointer, " [%s]", dm->name);
		dm = dm->next;
	}

	fprintf(gHostFilePointer, "\n");

}

int main(int argc, char **argv)
{
	pcap_t *fp = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	WSADATA wsd;
	char *last;
	char FileName[MAX_PATH];

	if (WSAStartup(0x0202, &wsd) != 0)
		exit(-1);

	GetModuleFileName(NULL, gPath, sizeof(gPath));
	last = strrchr(gPath, '\\');
	*(last + 1) = '\0';

	sprintf_s(FileName, sizeof(FileName), "%sHostStat.txt", gPath);
	memset(&gPcapCtx, 0, sizeof(gPcapCtx));
	HostListInit(&gPcapCtx.h_list, get_host_info, dump_host_info);
	
	if (argc < 3)
		Usage();

	if (!strcmp(argv[1], "-r")) {
		fp = pcap_open_offline(argv[2], errbuf);
	}
	else if (!strcmp(argv[1], "-i")) {
		gPcapCtx.live = 1;
		fp = pcap_open_live(argv[2], 65536, 1, 0, errbuf);
	}
	else {
		Usage();
	}

	if (fp == NULL) {
		printf("error: %s\n", errbuf);
		return -1;
	}

	gPcapCtx.link_type = pcap_datalink(fp);
	if (gPcapCtx.link_type != DLT_EN10MB && gPcapCtx.link_type != DLT_RAW) {
		printf("data link type no supported\n");
		pcap_close(fp);
		return -1;
	}

	do {

		if (load_host_file(FileName))
			break;

		if (fopen_s(&gHostFilePointer, FileName, "w"))
			return -1;

		if (!qqwrydb_open("c:\\qqwry.dat"))
			break;

		pcap_loop(fp, 0, pcap_callback, (u_char *)&gPcapCtx);

		
	} while ( 0 );

	pcap_close(fp);

	HostListDestroy(&gPcapCtx.h_list);

	qqwryda_close();

	WSACleanup();

	if (gHostFilePointer)
		fclose(gHostFilePointer);

	return 0;
}
