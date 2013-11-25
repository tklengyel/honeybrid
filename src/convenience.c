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
/*!	\file convenience.c
 \brief

 This file is intended to provide a place for the convenience functions
 to be placed at.

 */

#include "types.h"
#include "log.h"
#include "constants.h"
#include "globals.h"
#include "structs.h"
#include "convenience.h"

/*! config_lookup
 /brief lookup values from the config hash table. Make sure the required value is present
 */

gpointer config_lookup(const char * parameter, gboolean required) {
	gpointer ret = g_hash_table_lookup(config, parameter);
	if (!ret && required) {
		errx(1, "Missing configuration parameter '%s'", parameter);
	}
	return ret;
}

gint intcmp(gconstpointer v1, gconstpointer v2,
		__attribute__((unused))     gconstpointer unused) {
	return (*(uint32_t *) v1 < (*(uint32_t *) v2) ? 1 :
			(*(uint32_t *) v1 == (*(uint32_t *) v2)) ? 0 : -1);
}

gint pincmp(gconstpointer v1, gconstpointer v2,
		__attribute__((unused))     gconstpointer unused) {

	return ((((struct pin_key *) v1)->key < ((struct pin_key *) v2)->key) ? 1 :
			(((struct pin_key *) v1)->key == ((struct pin_key *) v2)->key) ?
					0 : -1);
}

gint conn_key_cmp(gconstpointer v1, gconstpointer v2,
		__attribute__((unused))     gconstpointer unused) {
	return ((((struct conn_key *) v1)->key < ((struct conn_key *) v2)->key) ?
			1 :
			(((struct conn_key *) v1)->key == ((struct conn_key *) v2)->key) ?
					0 : -1);
}

status_t switch_state(struct conn_struct *conn, conn_status_t new_state) {

	printdbg(
			"%s switching state from %s to %s\n",
			H(conn->id), lookup_state(conn->state), lookup_state(new_state));

	conn->state = new_state;

	return OK;
}

void free_f_0(void **x) {
	if (*x) {
		free(*x);
		*x = NULL;
	}
}

void ips2strings(const ip_addr_t *src, const ip_addr_t *dst, char **srcstr, char **dststr) {
	if (likely(src && dst && srcstr && dststr)) {
		inet_ntop(AF_INET, &src, *srcstr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &dst, *dststr, INET_ADDRSTRLEN);
	}
}


