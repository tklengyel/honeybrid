/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu>
 * and Julien Vehent <julien@linuxwall.info>
 *
 * 2012-2014 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
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

#ifndef __CONSTANTS_H_
#define __CONSTANTS_H_

#include "types.h"

extern const char banner[];

extern const char* protocol_string[IPPROTO_MAX];

extern const char* role_string[__MAX_ROLE];

extern const char* conn_status_string[__MAX_CONN_STATUS];

extern const char* mod_result_string[];

extern const char mac_broadcast_string[];

static inline const char *lookup_proto(uint8_t proto) {
	return protocol_string[proto];
}

static inline const char *lookup_role(role_t role) {
	return role_string[role];
}

static inline const char *lookup_state(conn_status_t state) {
	return conn_status_string[state];
}

static inline const char *lookup_result(mod_result_t result) {
	return mod_result_string[result];
}

#endif /* __CONSTANTS_H_ */
