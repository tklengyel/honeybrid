/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
 * (Extended by Tamas K Lengyel <tamas.k.lengyel@gmail.com>
 *
 * Honeybrid is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CONVENIENCE_H_
#define __CONVENIENCE_H_

#include "types.h"

gpointer config_lookup(const char * parameter, gboolean required);

gint intcmp(gconstpointer a, gconstpointer b, gconstpointer c);
gint pincmp(gconstpointer a, gconstpointer b, gconstpointer c);
gint conn_key_cmp(gconstpointer a, gconstpointer b, gconstpointer c);

#define ghashtable_foreach(table, i, key, val) \
        g_hash_table_iter_init(&i, table); \
        while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

#define CONFIG(parameter) \
	(const char *)(config_lookup(parameter, FALSE))

#define CONFIG_REQUIRED(parameter) \
	(const char *)(config_lookup(parameter, TRUE))

#define ICONFIG(parameter) \
	(config_lookup(parameter, FALSE) ? *(const int *)config_lookup(parameter, FALSE) : NOK)

#define ICONFIG_REQUIRED(parameter) \
	*(const int *)config_lookup(parameter, TRUE)

#define likely(x)    __builtin_expect (!!(x), 1)
#define unlikely(x)  __builtin_expect (!!(x), 0)

status_t switch_state(struct conn_struct *conn, conn_status_t new_state);

#define free_0(x) if(x) { free(x); x = NULL; }

void free_f_0(void **x);

void ips2strings(const ip_addr_t *src, const ip_addr_t *dst, char **srcstr, char **dststr);

// Calling this macro will allocate the strings on the stack
// so there is no need to free them
#define GET_IP_STRINGS(_src, _dst, _srcstr, _dststr) \
	do { \
		_srcstr = alloca(INET_ADDRSTRLEN); \
		_dststr = alloca(INET_ADDRSTRLEN); \
		inet_ntop(AF_INET, &_src, _srcstr, INET_ADDRSTRLEN); \
		inet_ntop(AF_INET, &_dst, _dststr, INET_ADDRSTRLEN); \
	} while(0)

#define CONN_KEY_FORMAT "%u:%u:%s:%u:%s:%u"

#define PRINT_CONN_KEYS(printf, format, tag, key1, key2) \
	do { \
		char *_key1_src, *_key1_dst, *_key2_src, *_key2_dst; \
		GET_IP_STRINGS(key1->src_ip, key1->dst_ip, _key1_src, _key1_dst); \
		GET_IP_STRINGS(key2->src_ip, key2->dst_ip, _key2_src, _key2_dst); \
		printf(format, tag, \
			key1->protocol, key1->vlan_id>>4, _key1_src, ntohs(key1->src_port), _key1_dst, ntohs(key1->dst_port), \
			key2->protocol, key2->vlan_id>>4, _key2_src, ntohs(key2->src_port), _key2_dst, ntohs(key2->dst_port) \
			); \
	} while(0)

#endif /* __CONVENIENCE_H_ */
