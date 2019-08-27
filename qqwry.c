#include <stdio.h>
#include <string.h>
#include "qqwry.h"

static FILE *qqwrydb_fp = NULL;
static unsigned long qqwry_ip_start = 0;
static unsigned long qqwry_ip_end = 0;

static unsigned long
qqwrydb_get_value(unsigned long start, int length);

int qqwrydb_open(const char *path)
{
	if (fopen_s(&qqwrydb_fp, path, "rb"))
		return 0;

	qqwry_ip_start = qqwrydb_get_value(0, 4);

	qqwry_ip_end = qqwrydb_get_value(4, 4);
	return 1;
}

void qqwryda_close(void)
{
	if (qqwrydb_fp) {
		fclose(qqwrydb_fp);
		qqwrydb_fp = NULL;
	}

	qqwry_ip_start = qqwry_ip_end = 0;
}

static unsigned long
qqwrydb_get_value(unsigned long start, int length)
{
	unsigned long variable = 0;
	int i;
	long buf[50] = { 0 };

	if (length > 50)
		return 0;

	if (fseek(qqwrydb_fp, start, SEEK_SET))
	{
		return 0;
	}

	for (i = 0; i < length; i++) {
		
		buf[i] = fgetc(qqwrydb_fp) & 0x000000FF;
	}

	for (i = length - 1; i >= 0; i--)
	{
		variable = variable * 256 + buf[i];
	}

	return variable;
}

static int
qqwrydb_get_string(unsigned long start, char *buf, size_t buflen)
{
	unsigned long len = 0;
	char ch;

	if (fseek(qqwrydb_fp, start, SEEK_SET) == 0) {
		do {
			if (len >= buflen)
				break;

			ch = (char)fgetc(qqwrydb_fp);
			buf[len++] = ch;
		} while (ch != 0x00);
	}

	return len;
}

static int qqwrydb_is_number(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	else
		return 0;
}

static unsigned long
qqwrydb_get_ip(const char *addr_str, int len)
{
	unsigned long ip = 0;
	int i, j = 0;

	for (i = 0; i < len; i++) {
		if (addr_str[i] == '.') {
			ip = ip * 256 + j;
			j = 0;
		}
		else {
		
			if (qqwrydb_is_number(addr_str[i])) {
				j = j * 10 + addr_str[i] - '0';
			}
			else {
				return 0;
			}
		}
	}

	return (ip * 256 + j);
}

static unsigned long
qqwrydb_search_ip(const unsigned long db_start,
	const unsigned long db_end, const unsigned long ip)
{
	unsigned long current, top, bottom;
	unsigned long record;

	bottom = db_start;
	top = db_end;

	current = ((top - bottom) / 7 / 2) * 7 + bottom;

	do {
		record = qqwrydb_get_value(current, 4);
		if (record > ip) {
			top = current;
			current = ((top - bottom) / 14) * 7 + bottom;
		}
		else {
			bottom = current;
			current = ((top - bottom) / 14) * 7 + bottom;
		}

	} while (bottom < current);

	return current;
}

int
qqwrydb_get_ipv4_geo_info(const char *ip_str, char *buf, size_t buflen)
{
	unsigned long redirect_address, country_address, location_address;
	char val;
	unsigned long ip, start, current;
	char country[100], location[100];

	memset(buf, 0, buflen);

	ip = qqwrydb_get_ip(ip_str, strlen(ip_str));
	if (ip == 0)
		return 0;

	current = qqwrydb_search_ip(qqwry_ip_start, qqwry_ip_end, ip);

	memset(country, 0, sizeof(country));
	memset(location, 0, sizeof(location));

	start = qqwrydb_get_value(current + 4, 3);
	start += 4;
	fseek(qqwrydb_fp, start, SEEK_SET);
	
	val = fgetc(qqwrydb_fp) & 0xFF;
	if (val == 1) {

		redirect_address = qqwrydb_get_value(start + 1, 3);
		fseek(qqwrydb_fp, redirect_address, SEEK_SET);

		if ((fgetc(qqwrydb_fp) & 0x000000FF) == 2) {
			country_address = qqwrydb_get_value(redirect_address + 1, 3);
			location_address = redirect_address + 4;
			qqwrydb_get_string(country_address, country, sizeof(country));
		}
		else {
			
			country_address = redirect_address;
			location_address = redirect_address +
				qqwrydb_get_string(country_address, country, sizeof(country));
		}
	}
	else if (val == 2) {
	
		country_address = qqwrydb_get_value(start + 1, 3);
		location_address = start + 4;
		qqwrydb_get_string(country_address, country, sizeof(country));
	}
	else {
		country_address = start;
		location_address = country_address +
			qqwrydb_get_string(country_address, country, sizeof(country));
	}

	fseek(qqwrydb_fp, location_address, SEEK_SET);

	if ((fgetc(qqwrydb_fp) & 0xFF) == 2 || (fgetc(qqwrydb_fp) & 0xFF) == 1) {
		location_address = qqwrydb_get_value(location_address + 1, 3);
	}

	qqwrydb_get_string(location_address, location, sizeof(location));
	sprintf_s(buf, buflen, "%s%s", country, location);

	return 1;
}
