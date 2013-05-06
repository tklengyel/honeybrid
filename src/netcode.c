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

/*! \file netcode.c
 \brief Network functions file

 \author Julien Vehent, 2007
 \author Thomas Coquelin, 2008
 */

#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <netinet/tcp.h>
//#include <netinet/ip.h>
//#include <netinet/udp.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "tables.h"
#include "netcode.h"

/*! in_cksum
 \brief Checksum routine for Internet Protocol family headers
 \param[in] addr a pointer to the data
 \param[in] len the 32 bits data size
 \return sum a 16 bits checksum
 */
unsigned short in_cksum(unsigned short *addr, int len) {
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;

	/*!
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/*! mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}

	/*! add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /*! add hi 16 to low 16 */
	sum += (sum >> 16); /*! add carry */
	answer = ~sum; /*! truncate to 16 bits */
	return (answer);
}

/*! send_raw
 \brief send a packet over a raw socket
 \param[in] p, the packet structure that contains the packet to be sent
 \return OK if the packet has been succesfully sent
 */

int send_raw(struct iphdr *p, uint32_t mark, struct interface *iface) {
	/*
	 #ifdef DEBUG
	 g_print("send_raw()\tCalled...\n");
	 #endif
	 */
	struct sockaddr_in dst;
	unsigned int bytes_sent;
	int sockettouse = 0;
	dst.sin_addr.s_addr = p->daddr;
	dst.sin_family = AF_INET;

	struct tcphdr *test = (struct tcphdr*) (((char *) p) + (p->ihl << 2));
	g_printerr("%s sending packet in raw socket: %s:%d -> ", H(4),
			inet_ntoa(*(struct in_addr *) &p->saddr), ntohs(test->source));
	g_printerr("%s:%d\n", inet_ntoa(*(struct in_addr *) &p->daddr),
			ntohs(test->dest));

	g_printerr("%s Sending raw packet to %s with mark %u\n", H(4),
			inet_ntoa(dst.sin_addr), mark);

	if (mark == 0 && iface == NULL) {
		if (p->protocol == 0x06)
			sockettouse = tcp_rsd;
		else if (p->protocol == 0x11)
			sockettouse = udp_rsd;
		else
			return NOK;
	} else {
		if (iface != NULL) {
			if (p->protocol == 0x06)
				sockettouse = iface->tcp_socket;
			else if (p->protocol == 0x11)
				sockettouse = iface->udp_socket;
			else
				return NOK;
		} else if (ICONFIG("multi_uplink") <= 1) {
			return NOK;
		} else {
			int link;
			for (link = 0; link < ICONFIG("multi_uplink"); link++) {
				if (uplinks[link].mark == mark) {
					if (p->protocol == 0x06)
						sockettouse = uplinks[link].tcp_socket;
					else if (p->protocol == 0x11)
						sockettouse = uplinks[link].udp_socket;
					else
						return NOK;
					break;
				}
			}
		}
	}

	bytes_sent = sendto(sockettouse, p, ntohs(p->tot_len), 0,
			(struct sockaddr *) &dst, sizeof(struct sockaddr_in));

	if (bytes_sent <= 0) {
		g_printerr("%s Packet not sent\n", H(4));
		return NOK;
	} else {
		g_printerr("%s Packet sent on socket %i, %u bytes\n", H(4), sockettouse,
				bytes_sent);
	}
	return OK;
}

/*! forward
 *
 \brief forward the packet to the attacker or to the HIH according to its origin
 \param[in] pkt, the packet metadata structure to forward

 \return OK if the packet has been succesfully sent
 */

int forward(struct pkt_struct* pkt) {
	struct iphdr* fwd = malloc(ntohs(pkt->packet.ip->tot_len));
	if (&fwd == (void*) 0x1)
		return NOK;

	memcpy(fwd, pkt->packet.ip, ntohs(pkt->packet.ip->tot_len));

	/*!If packet from HIH, we forward it to EXT with LIH source*/
	if (pkt->origin == HIH) {
		g_printerr("%s forwarding packet to EXT\n", H(pkt->conn->id));
		/*!We set LIH source IP*/
		fwd->saddr = pkt->conn->hih.lih_addr;
		/*!If TCP, we update the source port, the sequence number, and the checksum*/
		if (fwd->protocol == 0x06) {
			((struct tcp_packet*) fwd)->tcp.source = pkt->conn->hih.port;
			((struct tcp_packet *) fwd)->tcp.seq =
					htonl(ntohl(pkt->packet.tcp->seq) + pkt->conn->hih.delta);
			tcp_checksum((struct tcp_packet*) fwd);
		}
		/*!If UDP, we update the source port and the checksum*/
		else if (fwd->protocol == 0x11) //udp
				{
			((struct udp_packet*) fwd)->udp.source = pkt->conn->hih.port;
			udp_checksum((struct udp_packet*) fwd);
		}

		hb_ip_checksum(fwd);
		send_raw(fwd, 0, NULL);

	}
	/*!If packet from EXT, we forward it to HIH*/
	else if (pkt->origin == EXT) {
		if (pkt->conn->hih.iface != NULL)
			g_printerr("%s forwarding packet to HIH %u on interface %s\n",
					H(pkt->conn->id), pkt->conn->hih.hihID,
					pkt->conn->hih.iface->name);

		fwd->daddr = pkt->conn->hih.addr;

		/*!If TCP, we update the destination port, the acknowledgement number if any, and the checksum*/
		if (fwd->protocol == 0x06) {
			((struct tcp_packet *) fwd)->tcp.dest = pkt->conn->hih.port;
			if (((struct tcp_packet *) fwd)->tcp.ack == 1) {
				((struct tcp_packet *) fwd)->tcp.ack_seq =
						htonl(ntohl(pkt->packet.tcp->ack_seq) + ~(pkt->conn->hih.delta) + 1);
			}
			tcp_checksum((struct tcp_packet*) fwd);
		}
		/*!If UDP, we update the destination port and the checksum*/
		else if (fwd->protocol == 0x11) {
			((struct udp_packet*) fwd)->udp.dest = pkt->conn->hih.port;
			udp_checksum((struct udp_packet*) fwd);
		}

		hb_ip_checksum(fwd);
		send_raw(fwd, pkt->mark, pkt->conn->hih.iface);
	}

	free(fwd);
	return OK;
}

/*! reply_reset
 *
 \brief creat a RST packet from a unexepcted packet and sends it with send_raw
 \param[in] p, the packet to which we reply the reset packet

 */

int reply_reset(struct packet *p) {
	int res;
	struct tcp_packet* rst = malloc(
			sizeof(struct iphdr) + sizeof(struct tcphdr));
	/*! reset only tcp connections */
	if (p->ip->protocol != 0x06) {
		g_printerr("%s Incorrect protocol: %d\n", H(4), p->ip->protocol);
		return NOK;
	}
	/*! fill up the IP header */
	rst->ip.version = 4;
	rst->ip.ihl = sizeof(struct iphdr) >> 2;
	rst->ip.tos = 0x0;
	rst->ip.tot_len = ntohs(sizeof(struct iphdr)+sizeof(struct tcphdr));
	rst->ip.id = 0x00;
	rst->ip.frag_off = ntohs(0x4000);
	rst->ip.ttl = 0x40;
	rst->ip.protocol = 0x06;
	rst->ip.check = 0x00;
	rst->ip.saddr = p->ip->daddr;
	rst->ip.daddr = p->ip->saddr;
	hb_ip_checksum((struct iphdr*) rst);

	/*! fill up the TCP header */
	rst->tcp.source = p->tcp->dest;
	rst->tcp.dest = p->tcp->source;
	if (p->tcp->ack == 1)
		rst->tcp.seq = (p->tcp->ack_seq);
	else
		rst->tcp.seq = 0x0;
	rst->tcp.ack_seq =
			htonl(ntohl(p->tcp->seq) + p->tcp->syn + p->tcp->fin + ntohs(p->ip->tot_len) - (p->ip->ihl << 2) - (p->tcp->doff << 2) );
	rst->tcp.res1 = 0x0;
	rst->tcp.doff = 0x5;
	rst->tcp.fin = 0x0;
	rst->tcp.syn = 0x0;
	rst->tcp.rst = 0x1;
	rst->tcp.psh = 0x0;
	rst->tcp.ack = 0x1;
	rst->tcp.urg = 0x0;
	rst->tcp.res2 = 0x0;
	rst->tcp.window = 0x00;
	rst->tcp.check = 0x00;
	rst->tcp.urg_ptr = 0x00;
	tcp_checksum(rst);
	res = send_raw((struct iphdr*) rst, 0, NULL);
	free(rst);
	return res;
}

/*! reset_lih
 *
 \brief reset the LIH when redirected to HIH
 \param[in] conn: the connnection that the LIH reset
 */

int reset_lih(struct conn_struct* conn) {
	int res = NOK;
	struct packet p;
	p.ip = NULL;
	struct pkt_struct* tmp;
	/*! find last packet from LIH*/
	g_printerr("%s Reseting LIH\n", H(conn->id));

	GSList * current = (GSList *) conn->BUFFER;
	do {
		tmp = (struct pkt_struct*) g_slist_nth_data(current, 0);
		if (tmp->origin == LIH)
			memcpy(&p, &tmp->packet, sizeof(struct packet));
	} while ((current = g_slist_next(current)) != NULL);
	if (p.ip == NULL) {
		g_printerr("%s no packet found from LIH\n", H(conn->id));
	} else
		/*! call reply_reset() with this packet*/
		res = reply_reset(&p);
	return res;
}

/*! replay
 *
 \brief reset the LIH when redirected to HIH
 \param[in] conn: the connnection being replayed
 \param[in] pkt: the packet from HIH to test

 */

int replay(struct conn_struct* conn, struct pkt_struct* pkt) {
	int de = 0;
	struct pkt_struct* current;

	g_printerr("%s Replay called\n", H(conn->id));

	if (pkt->origin != HIH) {
		free_pkt(pkt);
		return NOK;
	}
	/*! If packet is from HIH and matches expected data then we replay the following packets from EXT to HIH until we find a packet from LIH*/
	if (test_expected(conn, pkt) == OK) {
		g_printerr("%s Looping over BUFFER\n", H(conn->id));
		current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
				conn->replay_id);
		de = current->DE;
		while (current->origin == EXT || de == 1) {
			g_printerr("%s --(Origin: %d)\n", H(conn->id), current->origin);
			if (current->origin == EXT)
				forward(current);
			if (g_slist_next(g_slist_nth( conn->BUFFER, conn->replay_id ))
					== NULL) {
				//g_static_rw_lock_writer_lock( &conn->lock );
				//conn->state = FORWARD;
				switch_state(conn, FORWARD);
				//g_static_rw_lock_writer_unlock( &conn->lock );
				free_pkt(pkt);
				return OK;
			}
			conn->replay_id++;
			current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
					conn->replay_id);
			if (de == 0) {
				de = current->DE;
			}
		}
		g_printerr("%s Defining expected data\n", H(conn->id));
		/*!Then we define expected data according to that packet*/
		define_expected_data(current);
		//g_static_rw_lock_writer_lock( &conn->lock );
		conn->replay_id++;
		//g_static_rw_lock_writer_unlock( &conn->lock );
	} else {
		free_pkt(pkt);
		return NOK;
	}
	free_pkt(pkt);
	return OK;
}

/*! hb_ip_checksum
 *
 \brief update the checksum in the IP header

 */
int hb_ip_checksum(struct iphdr* hdr) {
	hdr->check = (unsigned short) in_cksum((unsigned short *) hdr,
			sizeof(struct iphdr));
	return OK;
}

/*! udp_checksum
 *
 \brief update the checksum in the UDP header

 */

int udp_checksum(struct udp_packet* hdr) {
	hdr->udp.check = (unsigned short) in_cksum((unsigned short *) hdr,
			sizeof(struct udphdr)); //UDPHSIZE + PKTSIZE + PSEUDOUDPHSIZE);
	return OK;
}

/*! define_expected_data
 *
 \brief define expected packet from HIH according to the packet from LIH
 \param[in] pkt: packet metadata used

 */
int define_expected_data(struct pkt_struct* pkt) {
	g_static_rw_lock_writer_lock(&pkt->conn->lock);
	pkt->conn->expected_data.ip_proto = pkt->packet.ip->protocol;
	if (pkt->packet.ip->protocol == 0x06) {
		pkt->conn->expected_data.tcp_seq = ntohl(pkt->packet.tcp->seq)
				+ ~pkt->conn->hih.delta + 1;
		pkt->conn->expected_data.tcp_ack_seq = ntohl(pkt->packet.tcp->ack_seq);

	}
	pkt->conn->expected_data.payload = pkt->packet.payload;
	g_static_rw_lock_writer_unlock(&pkt->conn->lock);
	return OK;
}

/*! test_expected
 *
 \brief get the packet from HIH, compare it to expected data, drop it and return the comparison result
 */
int test_expected(struct conn_struct* conn, struct pkt_struct* pkt) {
	int flag = NOK;
	/*! lock the structure
	 g_static_rw_lock_writer_lock( &conn->lock );
	 */

	if (pkt->packet.ip->protocol != conn->expected_data.ip_proto) {
		flag = NOK;
		g_printerr("%s Unexpected protocol: %d\n", H(conn->id),
				pkt->packet.ip->protocol);

		conn->replay_problem = conn->replay_problem | 8;
	} else if ((pkt->packet.ip->protocol == 0x06) && (pkt->packet.tcp->syn == 0)
			&& (ntohl(pkt->packet.tcp->seq) != conn->expected_data.tcp_seq)) {
		flag = NOK;
		g_printerr("%s Unexpected TCP seq. number: %u. Expected: %u\n",
				H(conn->id), ntohl(pkt->packet.tcp->seq),
				conn->expected_data.tcp_seq);

		conn->replay_problem = conn->replay_problem | 4;
	} else if ((pkt->packet.ip->protocol == 0x06)
			&& (ntohl(pkt->packet.tcp->ack_seq)
					!= conn->expected_data.tcp_ack_seq)) {
		flag = NOK;
		g_printerr("%s Unexpected TCP ack. number\n", H(conn->id));
		conn->replay_problem = conn->replay_problem | 2;
	} else if ((pkt->packet.ip->protocol == 0x06)
			&& (!strncmp(pkt->packet.payload, conn->expected_data.payload,
					pkt->data) == 0)) {
		flag = OK;
		g_printerr("%s Unexpected payload\n", H(conn->id));
		conn->replay_problem = conn->replay_problem | 1;
	} else {
		flag = OK;
		g_printerr("%s Expected data OK\n", H(conn->id));
	}

	/*! free the lock
	 g_static_rw_lock_writer_unlock( &conn->lock );
	 */

	return flag;
}

/*! init_raw_sockets
 \brief create the two raw sockets for UDP/IP and TCP/IP
 *
 \return OK
 */

int init_raw_sockets() {

	int opt = 1;
	/*! create the two raw sockets for UDP/IP and TCP/IP, packets sent through these will be routed normally
	 */
	tcp_rsd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	udp_rsd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

	setsockopt(tcp_rsd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
	setsockopt(udp_rsd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

	/* Configure multi-uplink sockets */
	if (ICONFIG("multi_uplink") > 1) {

		uplinks = (struct interface *) malloc(
				ICONFIG("multi_uplink") * sizeof(struct interface));

		int init = 0;
		for (init = 0; init < ICONFIG("multi_uplink") && init < 10; init++) {
			char *config_ifvar = (char*) malloc(13 * sizeof(char));
			snprintf(config_ifvar, 13, "uplink%d_name", init + 1);
			uplinks[init].name = (char *) malloc(32 * sizeof(char));
			snprintf(uplinks[init].name, 32, "%s",
					(char *) g_hash_table_lookup(config, config_ifvar));
			snprintf(config_ifvar, 13, "uplink%d_mark", init + 1);
			uplinks[init].mark = ICONFIG(config_ifvar);
			free(config_ifvar);

			g_printerr(
					"%s Opening sockets on interface %s (routing with mark %i)\n",
					H(0), uplinks[init].name, uplinks[init].mark);
			uplinks[init].tcp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
			uplinks[init].udp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

			setsockopt(uplinks[init].tcp_socket, IPPROTO_IP, IP_HDRINCL, &opt,
					sizeof(opt));
			setsockopt(uplinks[init].udp_socket, IPPROTO_IP, IP_HDRINCL, &opt,
					sizeof(opt));

			if (setsockopt(uplinks[init].tcp_socket, SOL_SOCKET,
					SO_BINDTODEVICE, uplinks[init].name,
					strlen(uplinks[init].name)) == 0)
				g_printerr(
						"%s TCP socket binding on %s with ID %i successfull\n",
						H(0), uplinks[init].name,
						uplinks[init].tcp_socket);
			else {
				g_printerr("%s TCP socket binding failed on %s with ID %i\n",
						H(0), uplinks[init].name,
						uplinks[init].tcp_socket);
				return NOK;
			}

			if (setsockopt(uplinks[init].udp_socket, SOL_SOCKET,
					SO_BINDTODEVICE, uplinks[init].name,
					strlen(uplinks[init].name)) == 0)
				g_printerr(
						"%s UDP socket binding on %s with ID %i successfull\n",
						H(0), uplinks[init].name,
						uplinks[init].udp_socket);
			else {
				g_printerr("%s UDP socket binding failed on %s with ID %i\n",
						H(0), uplinks[init].name,
						uplinks[init].udp_socket);
				return NOK;
			}
		}

	}

	/* Open backend sockets for defined interfaces */
	g_ptr_array_foreach(targets, (GFunc) init_raw_sockets_backends,
			(gpointer) &opt);

	return OK;
}

/* Loop through each target */
void init_raw_sockets_backends(gpointer target, gpointer opt) {
	g_tree_foreach(((struct target *) target)->back_ifs,
			(GTraverseFunc) init_raw_sockets_backends2, opt);
}

/* Loop through each backend interface*/
gboolean init_raw_sockets_backends2(gpointer key, gpointer value, gpointer opt) {
	struct interface *iface = (struct interface *) value;
	g_printerr("%s Opening backend sockets on interface %s\n", H(0),
			iface->name);
	iface->tcp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	iface->udp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

	setsockopt(iface->tcp_socket, IPPROTO_IP, IP_HDRINCL, (int*) opt,
			sizeof(*(int*) opt));
	setsockopt(iface->udp_socket, IPPROTO_IP, IP_HDRINCL, (int*) opt,
			sizeof(*(int*) opt));

	if (setsockopt(iface->tcp_socket, SOL_SOCKET, SO_BINDTODEVICE, iface->name,
			strlen(iface->name)) == 0)
		g_printerr("%s TCP socket binding on %s with ID %i successfull\n", H(0),
				iface->name, iface->tcp_socket);
	else
		g_printerr("%s TCP socket binding failed on %s with ID %i\n", H(0),
				iface->name, iface->tcp_socket);

	if (setsockopt(iface->udp_socket, SOL_SOCKET, SO_BINDTODEVICE, iface->name,
			strlen(iface->name)) == 0)
		g_printerr("%s UDP socket binding on %s with ID %i successfull\n", H(0),
				iface->name, iface->udp_socket);
	else
		g_printerr("%s UDP socket binding failed on %s with ID %i\n", H(0),
				iface->name, iface->udp_socket);

	return 0;
}

/*!
 * test for a new tcp checksum function
 \param[in] pkt: packet to compute the checksum
 \return OK
 */
int tcp_checksum(struct tcp_packet* pkt) {
	/*struct in_addr s_in;
	struct in_addr d_in;
	s_in.s_addr = pkt->ip.saddr;
	d_in.s_addr = pkt->ip.daddr;*/

	int padd = (pkt->ip.tot_len) & 1;
	pkt->tcp.check = 0x00;

	struct tcp_chk_packet chk_p;
	memset(&chk_p, 0x0, sizeof(struct tcp_chk_packet) + padd);
	unsigned short TOT_SIZE = ntohs(pkt->ip.tot_len);
	unsigned short IPHDR_SIZE = (pkt->ip.ihl << 2);
	unsigned short TCPHDRDATA_SIZE = TOT_SIZE - IPHDR_SIZE;
	unsigned short len_tcp = TCPHDRDATA_SIZE;

	chk_p.pseudohdr.saddr = pkt->ip.saddr;
	chk_p.pseudohdr.daddr = pkt->ip.daddr;
	chk_p.pseudohdr.res1 = 0;
	chk_p.pseudohdr.proto = IPPROTO_TCP;
	chk_p.pseudohdr.tcp_len = htons( len_tcp );

	memcpy(&chk_p.tcp, &pkt->tcp, sizeof(struct tcphdr));
	memcpy(&chk_p.payload, &pkt->payload, len_tcp - sizeof(struct tcphdr));

	pkt->tcp.check = (unsigned short) in_cksum((unsigned short *) &chk_p,
			sizeof(struct pseudotcphdr) + len_tcp);

	return OK;
}

/*! addr2int
 * \brief Convert an IP address from string to int
 * \param[in] the IP address (string format)
 *
 * \return the IP address (int format)
 */
int addr2int(char *address) {
	gchar **addr;
	int intaddr;

	if (address == NULL) {
		g_printerr("%s Error, null address can't be converted!\n", H(0));
		return -1;
	}

	addr = g_strsplit(address, ".", 0);

	intaddr = atoi(addr[0]) << 24;
	intaddr += atoi(addr[1]) << 16;
	intaddr += atoi(addr[2]) << 8;
	intaddr += atoi(addr[3]);
	g_strfreev(addr);
	return intaddr;
}

