/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
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
int udp_rsd,tcp_rsd;

struct pseudotcphdr
{
	int saddr;
	int daddr;
	short res1:8;
	short proto:8;
	short tcp_len;
};

struct tcp_chk_packet
{
	struct pseudotcphdr pseudohdr;
	struct tcphdr tcp;
	char payload[BUFSIZE];
};

int send_raw(struct iphdr *p);

int forward(struct pkt_struct* pkt);

int reply_reset(struct packet p);

int reset_lih(struct conn_struct* connection_data);

int replay(struct conn_struct* connection_data, struct pkt_struct* pkt);

int hb_ip_checksum(struct iphdr* hdr);

int tcp_checksum(struct tcp_packet* pkt);

int udp_checksum(struct udp_packet* hdr);

int define_expected_data(struct pkt_struct* pkt);

int test_expected(struct conn_struct* connection_data, struct pkt_struct* pkt);

int init_raw_sockets();

#endif // _NETCODE_H_
