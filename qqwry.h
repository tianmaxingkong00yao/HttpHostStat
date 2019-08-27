#ifndef __QQWRY_H
#define __QQWRY_H

int qqwrydb_open(const char *path);

void qqwryda_close(void);

int
qqwrydb_get_ipv4_geo_info(const char *ip_str, char *buf, size_t buflen);

#endif
