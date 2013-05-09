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

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#include "tables.h"
#include "types.h"

/*!
 \def BUFSIZE
 *
 * number of bytes in the payload we want to copy to userspace
 * a regular ethernet connection limit payload size to 1500 bytes
 */
#define BUFSIZE 2048

#define ip_checksum(hdr) \
	((struct iphdr*)hdr)->check = \
		in_cksum(hdr, \
		sizeof(struct iphdr))

#define udp_checksum(hdr) \
	((struct udp_packet *)hdr)->udp.check = \
		in_cksum( hdr, \
        sizeof(struct udphdr))

/*!
 \def udp_rsd
 *
 \brief Raw socket descriptor for UDP/IP raw socket
 *
 */

/*!
 \def tcp_rsd
 *
 \brief Raw socket descriptor for TCP/IP raw socket
 *
 */
int udp_rsd, tcp_rsd; // generic socket

struct pseudotcphdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t res1;
	uint8_t proto;
	uint16_t tcp_len;
} __attribute__ ((packed));

struct tcp_chk_packet {
	struct pseudotcphdr pseudohdr;
	struct tcphdr tcp;
	char payload[BUFSIZE];
} __attribute__ ((packed));

struct interface *uplinks;

status_t send_raw(struct iphdr *p, struct interface *iface);

status_t forward(struct pkt_struct* pkt);

status_t reply_reset(const struct packet *p);

status_t reset_lih(struct conn_struct* connection_data);

status_t replay(struct conn_struct* connection_data, struct pkt_struct* pkt);

status_t tcp_checksum(struct tcp_packet* pkt);

status_t define_expected_data(struct pkt_struct* pkt);

status_t test_expected(struct conn_struct* connection_data, struct pkt_struct* pkt);

status_t init_raw_sockets();

void init_raw_sockets_backends(gpointer target, gpointer extra);

gboolean init_raw_sockets_backends2(gpointer key, gpointer value, gpointer extra);

int addr2int(const char *address);

#endif // _NETCODE_H_
