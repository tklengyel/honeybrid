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

#ifndef _NETCODE_H_
#define _NETCODE_H_

#include "types.h"
#include "structs.h"

status_t proxy(struct pkt_struct* pkt);

status_t forward_hih(struct pkt_struct* pkt);

status_t forward_ext(struct pkt_struct* pkt);

void reply_reset(struct pkt_struct *pkt, struct interface *iface);

void reset_lih(struct conn_struct* connection_data);

status_t replay(struct conn_struct* connection_data, struct pkt_struct* pkt);

void define_expected_data(struct pkt_struct* pkt);

status_t test_expected(struct conn_struct* connection_data, struct pkt_struct* pkt);

void set_iface_info(struct interface *iface);

void send_arp_reply(struct interface *iface, const u_char *packet);

#endif // _NETCODE_H_
