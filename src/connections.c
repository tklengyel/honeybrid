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

#include "connections.h"
#include <ctype.h>
#include "constants.h"
#include "netcode.h"
#include "log.h"
#include "globals.h"
#include "convenience.h"

/*!	\file connections.c
 \brief

 All network connection related functions are placed here.
 These functions are responsible for flow-tracking,
 redirection and expiration/cleanup.

 */

#define tcp_ack_only(tcp) \
	(tcp->ack && !(tcp->fin || tcp->psh || tcp->rst || tcp->syn || tcp->urg))

#define pkt_vlan_id(pkt) \
    (pkt->packet.eth->ether_type==htons(ETHERTYPE_IP)?0:pkt->packet.vlan->h_vlan_TCI.vid)

/*! init_pkt
 \brief init the current packet structure with meta-information such as the origin and the number of bytes of data
 \param[in] nf_packet: The raw packet from the queue
 \param[in] pkt: The packet metadata structure for this packet
 \param[in] mark: Netfilter mark of the packet
 \return the origin of the packet
 */
status_t init_pkt(struct interface *iface, uint16_t ethertype,
		const struct pcap_pkthdr *header, const u_char *packet,
		struct pkt_struct **pkt_out) {

	status_t ret = NOK;

	struct pkt_struct *pkt = g_malloc0(sizeof(struct pkt_struct));

	/* Init a new structure for the current packet */
	pkt->in = iface;

	/*! Assign the packet IP header and payload to the packet structure */
	if (ethertype == ETHERTYPE_IP) {

		/* Save the packet with enough room to add a VLAN header if needed */
		pkt->packet.FRAME = malloc(header->caplen + VLAN_HLEN);
		memcpy(pkt->packet.FRAME + VLAN_HLEN, packet, header->caplen);
		pkt->packet.eth =
				(struct ether_header *) (pkt->packet.FRAME + VLAN_HLEN);

		pkt->original_headers.eth = g_memdup(pkt->packet.eth, ETHER_HDR_LEN);
		pkt->packet.ip = (struct iphdr *) ((char *) pkt->packet.eth
				+ ETHER_HDR_LEN);

		pkt->size = ETHER_HDR_LEN;
	} else if (ethertype == ETHERTYPE_VLAN) {

		pkt->packet.FRAME = malloc(header->caplen);
		memcpy(pkt->packet.FRAME, packet, header->caplen);
		pkt->packet.vlan = (struct vlan_ethhdr *) (pkt->packet.FRAME);

		pkt->original_headers.vlan = g_memdup(pkt->packet.vlan, VLAN_ETH_HLEN);
		pkt->packet.ip = (struct iphdr *) ((char *) pkt->packet.vlan
				+ VLAN_ETH_HLEN);

		pkt->size = VLAN_ETH_HLEN;
	}

	pkt->size += ntohs(pkt->packet.ip->tot_len);

	if (pkt->size > header->caplen) {
		pkt->fragmented = TRUE;
	}

	if (!memcmp(&pkt->packet.eth->ether_dhost, &broadcast.addr_eth, ETH_ALEN)) {
		pkt->broadcast = TRUE;
	}

	pkt->original_headers.ip = g_memdup(pkt->packet.ip,
			(pkt->packet.ip->ihl << 2));

	if (pkt->packet.ip->protocol == IPPROTO_TCP) {
		/*! Process TCP packets */

		pkt->packet.tcp = (struct tcphdr*) (((char *) pkt->packet.ip)
				+ (pkt->packet.ip->ihl << 2));

		if (pkt->size < MIN_TCP_SIZE) {
			printdbg("%s Invalid TCP header length. Skipped.\n", H(4));

			goto done;
		}

		if (pkt->packet.tcp->doff < 0x05 || pkt->packet.tcp->doff > 0xFF) {
			printdbg(
					"%s Invalid TCP header length: %u. Skipped.\n", H(4), pkt->packet.tcp->doff);

			goto done;
		}
		if (pkt->packet.tcp->source == 0 || pkt->packet.tcp->dest == 0) {
			printdbg("%s Invalid TCP ports. Skipped.\n", H(4));

			goto done;
		}

		pkt->original_headers.tcp = g_memdup(pkt->packet.tcp,
				sizeof(struct tcphdr));

		pkt->packet.payload = (char*) pkt->packet.tcp
				+ (pkt->packet.tcp->doff << 2);

		/* The volume of data is the total size of the packet minus the size of the IP and TCP headers */
		pkt->data = ntohs(pkt->packet.ip->tot_len) - (pkt->packet.ip->ihl << 2)
				- (pkt->packet.tcp->doff << 2);

	} else if (pkt->packet.ip->protocol == IPPROTO_UDP) {
		/*! Process UDP packet */

		pkt->packet.udp = (struct udphdr*) (((char *) pkt->packet.ip)
				+ (pkt->packet.ip->ihl << 2));

		pkt->original_headers.udp = g_memdup(pkt->packet.udp,
				sizeof(struct udphdr));

		pkt->packet.payload = (char*) pkt->packet.udp + UDP_HDR_LEN;

		pkt->data =
				ntohs(
						pkt->packet.ip->tot_len) - (pkt->packet.ip->ihl << 2) - UDP_HDR_LEN;

}				else {
					printdbg("%s Invalid protocol: %u, packet skipped\n", H(4), pkt->packet.ip->protocol);

					goto done;
				}

		// Check if the packet comes from a target interface
	if (pkt->in->target) {
		pkt->origin = EXT;
	} else {
		// Packet came from an interface that's not assigned as a target default route
		// That means it's an internal honeynet interface, so packet is either from LIH or HIH
		// but we don't know which (yet)
		pkt->origin = INT;
	}

	ret = OK;

	done: if (ret == NOK) {
		free_pkt(pkt);
	} else {
		*pkt_out = pkt;
	}

	return ret;
}

/*! free_pkt
 \brief free the current packet structure
 \param[in] pkt: struct pkt_struct to free
 */
void free_pkt(struct pkt_struct *pkt) {
	free_0(pkt->original_headers.eth);
	free_0(pkt->original_headers.vlan);
	free_0(pkt->original_headers.ip);
	free_0(pkt->original_headers.tcp);
	free_0(pkt->original_headers.udp);
	free_0(pkt->packet.FRAME);
	free_0(pkt);
}

/*! store_pkt function
 \brief Store the current packet as part of the connection to replay it later.
 *
 \param[in] pkt: struct pkt_struct to work with
 \param[in] conn: struct conn_struct to work with
 *
 \return the position of the packet in the list in case of success, a negative value if storage has failed
 */
status_t store_pkt(struct conn_struct *conn, struct pkt_struct *pkt) {

	status_t ret = NOK;
	guint length;
	pkt->position = -1;

	length = g_slist_length(conn->BUFFER);

	if (length < max_packet_buffer) {

		/*! Append pkt to the singly-linked list of conn */
		conn->BUFFER = g_slist_append(conn->BUFFER, pkt);

		/*! Get the packet position */
		pkt->position = length;

		ret = OK;
	}

	if (ret == OK) {
		printdbg(
				"%s\t Packet stored in memory for connection %u\n", H(conn->id), conn->id);
	}

	return ret;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("\t%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*! print_payload
 */
void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16; /* number of bytes per line */
	int line_len;
	int offset = 0; /* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

gboolean find_hih_src(uint64_t *hihID, struct handler *back_handler,
		struct hih_search *s) {

	if (hihID && back_handler && back_handler->iface == s->pkt->in
			&& back_handler->ip->addr_ip == s->pkt->packet.ip->saddr
			&& ((s->pkt->packet.eth->ether_type == htons(ETHERTYPE_IP)
					&& back_handler->vlan.vid == 0)
					|| (s->pkt->packet.eth->ether_type == htons(ETHERTYPE_VLAN)
							&& back_handler->vlan.vid
									== s->pkt->packet.vlan->h_vlan_TCI.vid))) {

		s->found = TRUE;
		s->hihID = *hihID;
		s->back_handler = back_handler;
		return TRUE;
	}
	return FALSE;
}

gboolean find_hih_dst(uint64_t *hihID, struct handler *back_handler,
		struct hih_search *s) {

	if (hihID && back_handler
			&& back_handler->ip->addr_ip == s->pkt->packet.ip->daddr) {

		s->found = TRUE;
		return TRUE;
	}
	return FALSE;
}

gboolean find_intra(struct addr *targetIP, struct handler *intra_handler,
		struct intra_search *s) {

	if (targetIP && intra_handler && intra_handler->iface == s->pkt->in
			&& intra_handler->ip->addr_ip == s->pkt->packet.ip->saddr
			&& ((s->pkt->packet.eth->ether_type == htons(ETHERTYPE_IP)
					&& intra_handler->vlan.vid == 0)
					|| (s->pkt->packet.eth->ether_type == htons(ETHERTYPE_VLAN)
							&& intra_handler->vlan.vid
									== s->pkt->packet.vlan->h_vlan_TCI.vid))) {

		s->found = TRUE;
		s->intra_handler = intra_handler;
		return TRUE;
	}
	return FALSE;
}

gboolean find_target(__attribute__ ((unused)) uint64_t *targetID,
		struct target *target, struct target_search *s) {

	struct pkt_struct *pkt = s->pkt;
	s->target = target;

	if (pkt->packet.ip->saddr == target->front_handler->ip->addr_ip) {
		printdbg(
				"%s This packet matches a LIH honeypot IP address of target with default route %s\n", H(0), target->default_route->tag);
		pkt->origin = LIH;
		s->found = TRUE;
		return TRUE;
	}

	g_tree_foreach(target->back_handlers, (GTraverseFunc) find_hih_src,
			s->hih_search);

	if (s->hih_search->found) {
		pkt->origin = HIH;
		s->found = TRUE;
		return TRUE;
	}

	g_tree_foreach(target->intra_handlers, (GTraverseFunc) find_intra,
			s->intra_search);

	if (s->intra_search->found) {
		pkt->origin = INTRA;
		s->found = TRUE;
		return TRUE;
	}

	return FALSE;
}

int conn_lookup(struct pkt_struct *pkt, struct conn_struct **conn_out) {

	int ret = 0;

#ifdef HONEYBRID_DEBUG
	char *src, *dst;
	GET_IP_STRINGS(pkt->packet.ip->saddr, pkt->packet.ip->daddr, src, dst);

	printdbg(
			"%s Looking for connection %s:%u -> %s:%u!\n", H(1), src, ntohs(pkt->packet.tcp->source), dst, ntohs(pkt->packet.tcp->dest));
#endif

	g_mutex_lock(&connlock);

	struct conn_key key;
	bzero(&key, sizeof(struct conn_key));
	key.protocol = pkt->packet.ip->protocol;
	key.src_ip = pkt->packet.ip->saddr;
	key.src_port = pkt->packet.tcp->source;
	key.dst_ip = pkt->packet.ip->daddr;
	key.dst_port = pkt->packet.tcp->dest;
	key.vlan_id = pkt_vlan_id(pkt);
	struct conn_struct *conn;

	if (pkt->origin == EXT) {

		//pkt->packet.ip->protocol, pkt->src_with_port, pkt->dst_with_port)

		// Check if it's an externally initiated connection
		if (g_tree_lookup_extended(ext_tree1, &key.key, NULL,
				(gpointer *) &conn)) {
			ret = 1;
			goto done;
		}

		// Check if it's an internally initiated connection
		if (g_tree_lookup_extended(int_tree2, &key.key, NULL,
				(gpointer *) &conn)) {
			ret = 1;
			goto done;
		}
	} else {

		// Check if it's an externally initiated connection going to INT
		if (g_tree_lookup_extended(ext_tree2, &key.key, NULL,
				(gpointer *) &conn)) {

			if (pkt->in == conn->target->front_handler->iface
					&& pkt->packet.ip->saddr
							== conn->target->front_handler->ip->addr_ip
					&& ((pkt->packet.eth->ether_type == htons(ETHERTYPE_IP)
							&& conn->target->front_handler->vlan.vid == 0)
							|| (pkt->packet.eth->ether_type
									== htons(ETHERTYPE_VLAN)
									&& conn->target->front_handler->vlan.vid
											== pkt->packet.vlan->h_vlan_TCI.vid))) {
				pkt->origin = LIH;
			} else {
				pkt->origin = HIH;
			}

			ret = 1;
			goto done;
		}

		// Check if it's an internally initiated connection going to EXT
		if (g_tree_lookup_extended(int_tree1, &key.key, NULL,
				(gpointer *) &conn)) {

			if (pkt->in == conn->target->front_handler->iface
					&& pkt->packet.ip->saddr
							== conn->target->front_handler->ip->addr_ip
					&& ((pkt->packet.eth->ether_type == htons(ETHERTYPE_IP)
							&& conn->target->front_handler->vlan.vid == 0)
							|| (pkt->packet.eth->ether_type
									== htons(ETHERTYPE_VLAN)
									&& conn->target->front_handler->vlan.vid
											== pkt->packet.vlan->h_vlan_TCI.vid))) {
				pkt->origin = LIH;
			} else {
				pkt->origin = HIH;
			}

			ret = 1;
			goto done;
		}

		// Check if it's an INT initiated connection going to INTRA
		if (g_tree_lookup_extended(intra_tree1, &key.key, NULL,
				(gpointer *) &conn)) {

			if (pkt->in == conn->target->front_handler->iface
					&& pkt->packet.ip->saddr
							== conn->target->front_handler->ip->addr_ip
					&& ((pkt->packet.eth->ether_type == htons(ETHERTYPE_IP)
							&& conn->target->front_handler->vlan.vid == 0)
							|| (pkt->packet.eth->ether_type
									== htons(ETHERTYPE_VLAN)
									&& conn->target->front_handler->vlan.vid
											== pkt->packet.vlan->h_vlan_TCI.vid))) {
				pkt->origin = LIH;
			} else {
				pkt->origin = HIH;
			}

			ret = 1;
			goto done;
		}

		// Check if it's an INTRA initiated connection
		if (g_tree_lookup_extended(intra_tree2, &key.key, NULL,
				(gpointer *) &conn)) {

			pkt->origin = INTRA;

			ret = 1;
			goto done;
		}
	}

	//TODO: Expire TCP connections if FINs were sent and then a new connection
	//      is reestablished with the same ports

	/*if (ret == 1 && pkt->packet.ip->protocol == IPPROTO_TCP) {
	 // Both sides sent TCP-FIN already
	 // We need to expire this connection and start a new one.
	 if ((*conn)->tcp_fin_in && (*conn)->tcp_fin_out
	 && !tcp_ack_only(pkt->packet.tcp)) {

	 printdbg("%s Expiring TCP connection manually.\n", H((*conn)->id));
	 //gint expire = 0;

	 *conn = NULL;
	 goto done;

	 } else if (pkt->packet.tcp->fin) {
	 if (pkt->origin == EXT) {
	 (*conn)->tcp_fin_in = TRUE;
	 } else {
	 (*conn)->tcp_fin_out = TRUE;
	 }
	 goto done;
	 }

	 if ((*conn)->tcp_fin_in
	 && pkt->origin == EXT&& !tcp_ack_only(pkt->packet.tcp)) {

	 printdbg
	 ("%s This incoming TCP connection has been closed but it's still sending non-ACK packets."
	 "This is VERY suspicious!\n",
	 H((*conn)->id));

	 }

	 if ((*conn)->tcp_fin_out
	 && pkt->origin != EXT&& !tcp_ack_only(pkt->packet.tcp)) {

	 printdbg
	 ("%s This outgoing TCP connection has been closed but it's still sending non-ACK packets."
	 "This is VERY suspicious!\n",
	 H((*conn)->id));

	 }
	 }*/

	done: if (ret) {
		g_mutex_lock(&conn->lock);
		*conn_out = conn;
	}
	g_mutex_unlock(&connlock);
	return ret;
}

status_t create_conn(struct pkt_struct *pkt, struct conn_struct **conn,
		gdouble microtime) {

	status_t result = NOK;
	struct conn_struct *conn_init = NULL;

	/*! The key could not be found, so we need to figure out where this packet comes from */
	if (pkt->packet.ip->protocol == IPPROTO_TCP && pkt->packet.tcp->syn == 0) {

#ifdef HONEYBRID_DEBUG
		do {
			char *src, *dst;
			GET_IP_STRINGS(pkt->packet.ip->saddr, pkt->packet.ip->daddr, src,
					dst);

			printdbg(
					"%s ~~~~ TCP packet without SYN: %s:%u -> %s:%u. Skipping.\n", H(0), src, ntohs(pkt->packet.tcp->source), dst, ntohs(pkt->packet.tcp->dest));
		} while (0);

#endif
		return result;
	}

	struct target *target = NULL;

	// If its a new external connection
	// the interface must have an assigned target.
	// All other new connections are going to be dropped.
	if (pkt->origin == EXT) {

		target = pkt->in->target;

		if (target) {
			goto conn_init;
		} else {
			goto done;
		}
	}

	// Determine where the packet is coming from

	struct hih_search hih_search;
	hih_search.found = FALSE;
	hih_search.pkt = pkt;

	struct intra_search intra_search;
	intra_search.found = FALSE;
	intra_search.pkt = pkt;

	struct target_search target_search;
	target_search.found = FALSE;
	target_search.pkt = pkt;
	target_search.hih_search = &hih_search;
	target_search.intra_search = &intra_search;

	g_rw_lock_reader_lock(&targetlock);
	g_tree_foreach(targets, (GTraverseFunc) find_target, &target_search);
	g_rw_lock_reader_unlock(&targetlock);

	if (target_search.found) {
		target = target_search.target;
		goto conn_init;
	}

	/*! this packet is for an unconfigured target, we drop it */
#ifdef HONEYBRID_DEBUG
	do {
		char *src, *dst;
		GET_IP_STRINGS(pkt->packet.ip->saddr, pkt->packet.ip->daddr, src, dst);

		printdbg(
				"%s No honeypot IP found for this packet: %s:%u -> %s:%u. Skipping for now.\n", H(0), src, ntohs(pkt->packet.tcp->source), dst, ntohs(pkt->packet.tcp->dest));
	} while (0);
#endif
	goto done;

	/*! initialize connection */
	conn_init: printdbg("%s Initializing connection structure\n", H(5));

	/*! Init new connection structure */
	conn_init = (struct conn_struct *) g_malloc0(sizeof(struct conn_struct));

	g_mutex_init(&conn_init->lock);
	g_mutex_lock(&conn_init->lock);

	/*! fill the structure */
	conn_init->target = target;
	conn_init->protocol = pkt->packet.ip->protocol;
	conn_init->access_time = microtime;
	conn_init->initiator = pkt->origin;
	conn_init->id = ++c_id;

	//conn_init->tcp_fin_in = FALSE;
	//conn_init->tcp_fin_out = FALSE;

	/*! statistics */
	conn_init->start_microtime = microtime;
	conn_init->stat_time[INIT] = microtime;
	conn_init->stat_packet[INIT] = 1;
	conn_init->stat_byte[INIT] = pkt->size;
	conn_init->total_packet = 1;
	conn_init->total_byte = pkt->size;
	conn_init->decision_rule = g_string_new("");

	addr_pack(&conn_init->first_pkt_src_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
			&pkt->packet.eth->ether_shost, ETH_ALEN);
	addr_pack(&conn_init->first_pkt_dst_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
			&pkt->packet.eth->ether_dhost, ETH_ALEN);
	addr_pack(&conn_init->first_pkt_src_ip, ADDR_TYPE_IP, 32,
			&pkt->packet.ip->saddr, sizeof(ip_addr_t));
	addr_pack(&conn_init->first_pkt_dst_ip, ADDR_TYPE_IP, 32,
			&pkt->packet.ip->daddr, sizeof(ip_addr_t));

	// Doesn't matter if its TCP or UDP, the ports are at the same location
	// in both headers
	conn_init->first_pkt_src_port = pkt->packet.tcp->source;
	conn_init->first_pkt_dst_port = pkt->packet.tcp->dest;

	struct tm *tm;
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);
	conn_init->start_timestamp = g_string_new("");
	g_string_printf(conn_init->start_timestamp,
			"%d-%02d-%02d %02d:%02d:%02d.%.6d", (1900 + tm->tm_year),
			(1 + tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
			(int) tv.tv_usec);

	//TODO: This is becoming a mess, split it up to sub-functions!

	if (pkt->origin == EXT) {
		conn_init->state = INIT;

		// New EXT connections always go to the LIH first
		conn_init->destination = LIH;

		// This is the incoming connection
		conn_init->ext_key = g_malloc0(sizeof(struct conn_key));
		conn_init->ext_key->protocol = pkt->packet.ip->protocol;
		conn_init->ext_key->src_ip = pkt->packet.ip->saddr;
		conn_init->ext_key->src_port = pkt->packet.tcp->source;
		conn_init->ext_key->dst_ip = pkt->packet.ip->daddr;
		conn_init->ext_key->dst_port = pkt->packet.tcp->dest;

		// This is what the reply will look like
		conn_init->int_key = g_malloc0(sizeof(struct conn_key));
		conn_init->int_key->protocol = pkt->packet.ip->protocol;
		conn_init->int_key->vlan_id = target->front_handler->vlan.vid;
		conn_init->int_key->src_ip = target->front_handler->ip->__addr_u.__ip;
		conn_init->int_key->src_port = pkt->packet.tcp->dest;
		conn_init->int_key->dst_ip = pkt->packet.ip->saddr;
		conn_init->int_key->dst_port = pkt->packet.tcp->source;

		conn_init->pin_key = g_malloc0(sizeof(struct pin_key));
		conn_init->pin_key->vlan_id = target->front_handler->vlan.vid;
		conn_init->pin_key->handler_ip = target->front_handler->ip->addr_ip;
		conn_init->pin_key->target_ip = pkt->packet.ip->daddr;

#ifdef HONEYBRID_DEBUG
		PRINT_CONN_KEYS(g_printerr,
				"%s Inserting new conn from EXT to dnat trees with keys "CONN_KEY_FORMAT" and "CONN_KEY_FORMAT"\n",
				H(conn_init->id), conn_init->ext_key, conn_init->int_key);
#endif

		g_mutex_lock(&connlock);
		g_tree_insert(ext_tree1, &conn_init->ext_key->key, conn_init);
		g_tree_insert(ext_tree2, &conn_init->int_key->key, conn_init);

		struct pin *pin = NULL;
		if (!g_tree_lookup_extended(comm_pin_tree, &conn_init->pin_key->key,
				NULL, (gpointer *) &pin)) {
			pin = malloc(sizeof(struct pin));
			pin->count = 1;
			pin->ip = conn_init->first_pkt_dst_ip;
			pin->pin_key = g_memdup(conn_init->pin_key, sizeof(struct pin_key));
			g_tree_insert(comm_pin_tree, pin->pin_key, pin);
#ifdef HONEYBRID_DEBUG
			do {
				char *src, *dst, *target, *handler;
				GET_IP_STRINGS(pkt->packet.ip->saddr, pkt->packet.ip->daddr,
						src, dst);
				GET_IP_STRINGS(pin->pin_key->target_ip,
						pin->pin_key->handler_ip, target, handler);
				printdbg(
						"%s Pinning %s with key %s:%s:%u\n", H(conn_init->id), dst, target, handler, ntohs(pin->pin_key->vlan_id));
			} while (0);
#endif

		} else {
			pin->count++;
		}
		g_mutex_unlock(&connlock);

		result = OK;

	} else if (pkt->origin == LIH) {
		conn_init->state = CONTROL;

		if (g_tree_lookup(conn_init->target->intra_handlers,
				&conn_init->first_pkt_dst_ip)) {
			conn_init->destination = INTRA;
			// Invalid destination
			goto done;
		} else {
			struct hih_search hih_search2;
			hih_search2.found = FALSE;
			hih_search2.pkt = pkt;
			g_tree_foreach(target->back_handlers, (GTraverseFunc) find_hih_dst,
					&hih_search2);

			if (hih_search2.found) {
				conn_init->destination = HIH;
				// Invalid destination
				goto done;
			} else {
				conn_init->destination = EXT;
			}
		}

		struct pin_key *comm_pin_key = g_malloc0(sizeof(struct pin_key));
		comm_pin_key->vlan_id = target->front_handler->vlan.vid;
		comm_pin_key->handler_ip = target->front_handler->ip->addr_ip;
		comm_pin_key->target_ip = pkt->packet.ip->daddr;

		ip_addr_t snat_to;
		struct pin *pin = g_tree_lookup(comm_pin_tree, comm_pin_key);
		if (!pin) {
			snat_to = target->default_route->ip->addr_ip;
			free(comm_pin_key);
		} else {
			snat_to = pin->ip.addr_ip;
			pin->count++;
			conn_init->pin_ip = &pin->ip;
			conn_init->pin_key = comm_pin_key;
		}

		conn_init->ext_key = g_malloc0(sizeof(struct conn_key));
		conn_init->ext_key->protocol = pkt->packet.ip->protocol;
		conn_init->ext_key->src_ip = pkt->packet.ip->daddr;
		conn_init->ext_key->src_port = pkt->packet.tcp->dest;
		conn_init->ext_key->dst_ip = snat_to;
		conn_init->ext_key->dst_port = pkt->packet.tcp->source;

		conn_init->int_key = g_malloc0(sizeof(struct conn_key));
		conn_init->int_key->protocol = pkt->packet.ip->protocol;
		conn_init->int_key->vlan_id = target->front_handler->vlan.vid;
		conn_init->int_key->src_ip = pkt->packet.ip->saddr;
		conn_init->int_key->src_port = pkt->packet.tcp->source;
		conn_init->int_key->dst_ip = pkt->packet.ip->daddr;
		conn_init->int_key->dst_port = pkt->packet.tcp->dest;

#ifdef HONEYBRID_DEBUG
		PRINT_CONN_KEYS(g_printerr,
				"%s Inserting new conn from LIH to snat trees with keys "CONN_KEY_FORMAT" and "CONN_KEY_FORMAT"\n",
				H(conn_init->id), conn_init->int_key, conn_init->ext_key);
#endif

		g_mutex_lock(&connlock);
		g_tree_insert(int_tree1, conn_init->int_key, conn_init);
		g_tree_insert(int_tree2, conn_init->ext_key, conn_init);
		g_mutex_unlock(&connlock);

		result = OK;

	} else if (pkt->origin == HIH) {

		conn_init->state = INIT;
		conn_init->hih.hihID = hih_search.hihID;
		conn_init->hih.back_handler = hih_search.back_handler;

		conn_init->intra_handler = g_tree_lookup(
				conn_init->target->intra_handlers,
				&conn_init->first_pkt_dst_ip);

		if (conn_init->intra_handler) {

			// This connection is a new conn that will be going to an INTRA target
			conn_init->destination = INTRA;
		} else if (hih_search.back_handler->netmask
				&& (conn_init->first_pkt_dst_ip.addr_ip
						& hih_search.back_handler->netmask->addr_ip)
						== (hih_search.back_handler->ip->addr_ip
								& hih_search.back_handler->netmask->addr_ip)) {

			// This is a connection intra-lan to an IP that is undefined at the moment
			// We skip the connection creation for now and go to the decision engine for help
			conn_init->destination = INTRA;
			result = OK;
			goto done;
		} else if (pkt->packet.ip->daddr == target->front_handler->ip->addr_ip) {
			conn_init->destination = LIH;
			// Invalid destination
			goto done;
		} else {
			struct hih_search hih_search2;
			hih_search2.found = FALSE;
			hih_search2.pkt = pkt;
			g_tree_foreach(target->back_handlers, (GTraverseFunc) find_hih_dst,
					&hih_search2);

			if (hih_search2.found) {
				conn_init->destination = HIH;
				// Invalid destination
				goto done;
			} else {
				conn_init->destination = EXT;
			}
		}

		if (conn_init->destination == EXT) {
			// HIH Connecting to EXT

			ip_addr_t snat_to;

			// With exclusive hihs we check the target_pin_tree
			if (exclusive_hih == 1) {
				struct pin_key *pin_key = g_malloc0(sizeof(struct pin_key));
				pin_key->vlan_id = hih_search.back_handler->vlan.vid;
				pin_key->handler_ip = hih_search.back_handler->ip->addr_ip;

				struct pin *pin = g_tree_lookup(target_pin_tree, pin_key);
				if (!pin) {
					// So this HIH is initiating a conn without redirection taking place first.
					// We will just take the default route's IP for this but we don't pin it
					snat_to = target->default_route->ip->addr_ip;
					free(pin_key);
				} else {
					snat_to = pin->ip.addr_ip;
					pin->count++;
					conn_init->pin_ip = &pin->ip;
					conn_init->pin_key = pin_key;
				}
			} else {
				// With non-exclusive HIHs, we check the comm_pin_tree

				struct pin_key *comm_pin_key = g_malloc0(
						sizeof(struct pin_key));
				comm_pin_key->vlan_id = target->front_handler->vlan.vid;
				comm_pin_key->handler_ip = target->front_handler->ip->addr_ip;
				comm_pin_key->target_ip = pkt->packet.ip->daddr;

				struct pin *pin = g_tree_lookup(comm_pin_tree, comm_pin_key);
				if (!pin) {
					snat_to = target->default_route->ip->addr_ip;
					free(comm_pin_key);
				} else {
					snat_to = pin->ip.addr_ip;
					pin->count++;
					conn_init->pin_ip = &pin->ip;
					conn_init->pin_key = comm_pin_key;
				}
			}

			// This is what the reply will look like
			conn_init->ext_key = g_malloc0(sizeof(struct conn_key));
			conn_init->ext_key->protocol = pkt->packet.ip->protocol;
			conn_init->ext_key->src_ip = pkt->packet.ip->daddr;
			conn_init->ext_key->src_port = pkt->packet.tcp->dest;
			conn_init->ext_key->dst_ip = snat_to;
			conn_init->ext_key->dst_port = pkt->packet.tcp->source;

			// This is the outgoing connection from the HIH
			conn_init->int_key = g_malloc0(sizeof(struct conn_key));
			conn_init->int_key->protocol = pkt->packet.ip->protocol;
			conn_init->int_key->vlan_id = hih_search.back_handler->vlan.vid;
			conn_init->int_key->src_ip = pkt->packet.ip->saddr;
			conn_init->int_key->src_port = pkt->packet.tcp->source;
			conn_init->int_key->dst_ip = pkt->packet.ip->daddr;
			conn_init->int_key->dst_port = pkt->packet.tcp->dest;

#ifdef HONEYBRID_DEBUG
			PRINT_CONN_KEYS(g_printerr,
					"%s Inserting new conn from HIH to snat trees with keys "CONN_KEY_FORMAT" and "CONN_KEY_FORMAT"\n",
					H(conn_init->id), conn_init->int_key, conn_init->ext_key);
#endif

			g_mutex_lock(&connlock);
			g_tree_insert(int_tree1, conn_init->int_key, conn_init);
			g_tree_insert(int_tree2, conn_init->ext_key, conn_init);
			g_mutex_unlock(&connlock);

			result = OK;
		} else if (conn_init->destination == INTRA) {
			// HIH Connecting to INTRA

			// Check if we have a pin for this
			// this is required to allow new connections back here from INTRA
			if (conn_init->intra_handler
					&& conn_init->intra_handler->exclusive) {
				struct pin_key *pin_key = g_malloc0(sizeof(struct pin_key));
				pin_key->vlan_id = conn_init->intra_handler->vlan.vid;
				pin_key->handler_ip = conn_init->intra_handler->ip->addr_ip;
				pin_key->target_ip = pkt->packet.ip->saddr;

				struct pin *pin = g_tree_lookup(intra_pin_tree, pin_key);
				if (!pin) {
					pin = malloc(sizeof(struct pin));
					pin->pin_key = pin_key;
					pin->count = 1;
					pin->ip = conn_init->first_pkt_dst_ip;
					conn_init->pin_ip = &pin->ip;
					conn_init->pin_key = pin_key;
					g_tree_insert(intra_pin_tree, pin->pin_key, pin);
				} else {
					if (pin->ip.addr_ip != conn_init->first_pkt_dst_ip.addr_ip) {
						// This INTRA is pinned to a different target IP
						printdbg(
								"%s Can't setup connection. INTRA is pinned to another target IP \n", H(conn_init->id));

						free(pin_key);
						goto done;
					} else {
						pin->count++;
						conn_init->pin_key = pin_key;
						conn_init->pin_ip = &pin->ip;
					}
				}
			}

			conn_init->intra_key = g_malloc0(sizeof(struct conn_key));
			conn_init->intra_key->protocol = pkt->packet.ip->protocol;
			conn_init->intra_key->vlan_id = conn_init->intra_handler->vlan.vid;
			conn_init->intra_key->src_ip = conn_init->intra_handler->ip->addr_ip;
			conn_init->intra_key->src_port = pkt->packet.tcp->dest;
			conn_init->intra_key->dst_ip = pkt->packet.ip->saddr;
			conn_init->intra_key->dst_port = pkt->packet.tcp->source;

			conn_init->int_key = g_malloc0(sizeof(struct conn_key));
			conn_init->int_key->protocol = pkt->packet.ip->protocol;
			conn_init->int_key->vlan_id = hih_search.back_handler->vlan.vid;
			conn_init->int_key->src_ip = pkt->packet.ip->saddr;
			conn_init->int_key->src_port = pkt->packet.tcp->source;
			conn_init->int_key->dst_ip = pkt->packet.ip->daddr;
			conn_init->int_key->dst_port = pkt->packet.tcp->dest;

#ifdef HONEYBRID_DEBUG
			PRINT_CONN_KEYS(g_printerr,
					"%s Inserting new conn from HIH to intra trees with keys "CONN_KEY_FORMAT" and "CONN_KEY_FORMAT"\n",
					H(conn_init->id), conn_init->int_key, conn_init->intra_key);
#endif

			g_mutex_lock(&connlock);
			g_tree_insert(intra_tree1, conn_init->int_key, conn_init);
			g_tree_insert(intra_tree2, conn_init->intra_key, conn_init);
			g_mutex_unlock(&connlock);

			result = OK;

		}

	} else if (pkt->origin == INTRA) {

		conn_init->state = PROXY;

		// Intra hosts can only initiate connections back to the HIH
		// and only if a HIH connected to them first
		// We don't set governing (control) rule on these connections, we just PROXY them
		// TODO?

		if (g_tree_lookup(conn_init->target->intra_handlers,
				&conn_init->first_pkt_dst_ip)) {
			conn_init->destination = INTRA;
			goto done;
		} else if (pkt->packet.ip->daddr == target->front_handler->ip->addr_ip) {
			conn_init->destination = LIH;
			goto done;
		} else {
			hih_search.found = FALSE;
			g_tree_foreach(target->back_handlers, (GTraverseFunc) find_hih_dst,
					&hih_search);

			if (hih_search.found) {

				conn_init->hih.back_handler = hih_search.back_handler;

				struct pin_key *pin_key = g_malloc0(sizeof(struct pin_key));
				pin_key->vlan_id = intra_search.intra_handler->vlan.vid;
				pin_key->target_ip = intra_search.intra_handler->ip->addr_ip;
				pin_key->handler_ip = conn_init->hih.back_handler->ip->addr_ip;

				struct pin *pin = g_tree_lookup(intra_pin_tree, pin_key);
				if (pin) {
					conn_init->pin_ip = &pin->ip;
					conn_init->pin_key = pin_key;
					conn_init->destination = HIH;
					pin->count++;
				} else {
					goto done;
				}
			} else {
				//TODO?
				conn_init->destination = EXT;
				goto done;
			}
		}

		ip_addr_t snat_to = conn_init->pin_ip->addr_ip;

		conn_init->int_key = g_malloc0(sizeof(struct conn_key));
		conn_init->int_key->protocol = pkt->packet.ip->protocol;
		conn_init->int_key->src_ip = pkt->packet.ip->daddr;
		conn_init->int_key->src_port = pkt->packet.tcp->dest;
		conn_init->int_key->dst_ip = snat_to;
		conn_init->int_key->dst_port = pkt->packet.tcp->source;

		conn_init->intra_key = g_malloc0(sizeof(struct conn_key));
		conn_init->intra_key->protocol = pkt->packet.ip->protocol;
		conn_init->intra_key->vlan_id = hih_search.back_handler->vlan.vid;
		conn_init->intra_key->src_ip = pkt->packet.ip->saddr;
		conn_init->intra_key->src_port = pkt->packet.tcp->source;
		conn_init->intra_key->dst_ip = pkt->packet.ip->daddr;
		conn_init->intra_key->dst_port = pkt->packet.tcp->dest;

#ifdef HONEYBRID_DEBUG
		PRINT_CONN_KEYS(g_printerr,
				"%s Inserting new conn from INTRA to intra trees with keys "CONN_KEY_FORMAT" and "CONN_KEY_FORMAT"\n",
				H(conn_init->id), conn_init->int_key, conn_init->intra_key);
#endif

		g_mutex_lock(&connlock);
		g_tree_insert(intra_tree1, conn_init->int_key, conn_init);
		g_tree_insert(intra_tree2, conn_init->intra_key, conn_init);
		g_mutex_unlock(&connlock);

		result = OK;

	}

	done: if (result == OK) {
		pkt->conn = conn_init;
		*conn = conn_init;
	} else {
		free_conn(conn_init);
	}

	return result;

}

status_t update_conn(struct pkt_struct *pkt, struct conn_struct *conn,
		gdouble microtime) {

	/*! The key was found in the B-Tree */
	printdbg("%s Connection %u found, updating\n", H(conn->id), conn->id);

	conn_status_t state = conn->state;

	/*! We store control statistics in the proxy mode */
	if (state == CONTROL) {
		state = PROXY;
	}

	/*! statistics */
	conn->stat_time[state] = microtime;
	conn->stat_packet[state] += 1;
	conn->stat_byte[state] += pkt->size;
	conn->total_packet += 1;
	conn->total_byte += pkt->size;
	/*! We update the current connection access time */
	conn->access_time = microtime;
	if (pkt->origin == EXT) {
		conn->count_data_pkt_from_intruder += 1;
	}

	pkt->conn = conn;
	return OK;
}

void remove_conn(struct conn_struct *conn, gpointer delayp) {

	int delay = GPOINTER_TO_INT(delayp);

	if (!delay) {
		// This connection must expire
		g_mutex_lock(&conn->lock);
	} else if (FALSE == g_mutex_trylock(&conn->lock)) {
		return;
	}

	if (conn->initiator == EXT) {
		g_tree_remove(ext_tree1, conn->ext_key);
		g_tree_remove(ext_tree2, conn->int_key);
		if (conn->hih.redirected_int_key) {
			g_tree_remove(ext_tree2, conn->hih.redirected_int_key);
		}

		struct pin *pin = NULL;
		if (conn->pin_key
				&& (pin = g_tree_lookup(comm_pin_tree, conn->pin_key))) {
			pin->count--;
			printdbg("%s Comm pin count @ %lu\n", H(1), pin->count);
			if (pin->count == 0) {
				printdbg("%s Removing comm pin\n", H(1));
				g_tree_remove(comm_pin_tree, conn->pin_key);
				free_pin(pin);
			}
		}
	} else if ((conn->initiator == LIH || conn->initiator == HIH)
			&& conn->destination == EXT) {
		g_tree_remove(int_tree2, conn->ext_key);
		g_tree_remove(int_tree1, conn->int_key);

		struct pin *pin = NULL;
		if (conn->pin_key
				&& (pin = g_tree_lookup(comm_pin_tree, conn->pin_key))) {
			pin->count--;
			printdbg("%s Comm pin count @ %lu\n", H(1), pin->count);
			if (pin->count == 0) {
				printdbg("%s Removing comm pin\n", H(1));
				g_tree_remove(comm_pin_tree, conn->pin_key);
				free_pin(pin);
			}
		}
	} else if (conn->initiator == INTRA
			|| (conn->initiator == HIH && conn->destination == INTRA)) {
		g_tree_remove(intra_tree1, conn->int_key);
		g_tree_remove(intra_tree2, conn->intra_key);

		struct pin *pin = NULL;
		if (conn->pin_key
				&& (pin = g_tree_lookup(intra_pin_tree, conn->pin_key))) {
			pin->count--;
			printdbg("%s Intra pin count @ %lu\n", H(1), pin->count);
			if (pin->count == 0) {
				printdbg("%s Removing intra pin\n", H(1));
				g_tree_remove(intra_pin_tree, conn->pin_key);
				free_pin(pin);
			}
		}
	}

	struct pin *pin = NULL;
	if (conn->hih.target_pin_key
			&& (pin = g_tree_lookup(target_pin_tree, conn->hih.target_pin_key))) {
		pin->count--;
		printdbg("%s HIH target pin count @ %lu\n", H(1), pin->count);
		if (pin->count == 0) {
			g_tree_remove(target_pin_tree, conn->pin_key);
			printdbg("%s Removing HIH target pin\n", H(1));
			free_pin(pin);
		}
	}

	connection_log(conn);
	free_conn(conn);
}

gboolean expire_conn(__attribute__ ((unused)) char *key,
		struct conn_struct *conn, gpointer delayp) {

	GTimeVal t;
	g_get_current_time(&t);
	int curtime = (t.tv_sec);
	int delay = GPOINTER_TO_INT(delayp);

	if ((curtime - conn->access_time > delay || conn->state < INIT)) {

		printdbg(
				"%s called with expiration delay on connection %u: %d\n", H(8), conn->id, delay);

		g_ptr_array_add(entrytoclean, conn);

	}

	return FALSE;
}

/*! init_conn
 \brief init the current context using the tuples.
 \param[in] pkt: struct pkt_struct to work with
 \param[in] conn: struct conn_struct to work with
 \return OK if success, NOK otherwise
 */
status_t init_conn(struct pkt_struct *pkt, struct conn_struct **conn) {

	/*! Get current time to update or create the structure */
	GTimeVal t;
	g_get_current_time(&t);
	gdouble microtime = 0.0;
	microtime += ((gdouble) t.tv_sec);
	microtime += (((gdouble) t.tv_usec) / 1000000.0);

	switch (conn_lookup(pkt, conn)) {
	case 0:
		return create_conn(pkt, conn, microtime);
	case 1:
		return update_conn(pkt, *conn, microtime);
	case -1:
	default:
		return NOK;
	}
}

/*! free_conn
 \brief called for each entry in the pointer array, each entry is a key that is deleted from the B-Tree
 \param[in] key, a pointer to the current B-Tree key value stored in the pointer table
 \param[in] trash, user data, unused
 */
void free_conn(struct conn_struct *conn) {
	if (conn) {

		uint32_t id = conn->id;

		GSList *current = conn->BUFFER;
		struct pkt_struct* tmp;
		if (current != NULL) {
			do {
				tmp = (struct pkt_struct*) g_slist_nth_data(current, 0);
				free_pkt(tmp);
			} while ((current = g_slist_next(current)) != NULL);

			g_slist_free(conn->BUFFER);
		}

		current = conn->custom_data;
		while (current != NULL) {
			struct custom_conn_data *custom =
					(struct custom_conn_data *) g_slist_nth_data(current, 0);
			if (custom) {
				if (custom->data && custom->data_free)
					custom->data_free(custom->data);

				free_0(custom);
			}

			current = g_slist_next(current);
		}

		g_slist_free(conn->custom_data);
		g_mutex_clear(&conn->lock);
		free_0(conn->int_key);
		free_0(conn->ext_key);
		free_0(conn->pin_key);
		free_0(conn->intra_key);
		free_0(conn->hih.redirected_int_key);
		free_0(conn->hih.target_pin_key);
		g_string_free(conn->start_timestamp, TRUE);
		g_string_free(conn->decision_rule, TRUE);
		free_0(conn);

		printdbg("%s Connection %u entry removed\n", H(8), id);
	}
}

/*! clean
 \brief watchman for the b_tree, wake up every minute and check every entries
 */
void clean() {

	int delay = ICONFIG("expiration_delay");
	if (delay <= 0)
		delay = 120;
	gint64 sleep_cycle;

	// Wait for timeout or signal
	g_mutex_lock(&threading_cond_lock);
	rewind: sleep_cycle = g_get_monotonic_time() + 60 * G_TIME_SPAN_SECOND;
	while (OK == threading) {
		if (!g_cond_wait_until(&threading_cond, &threading_cond_lock,
				sleep_cycle)) {

			printdbg("%s cleaning\n", H(8));

			/*! init the table*/
			entrytoclean = g_ptr_array_new();

			/*! call the clean function for each value */
			g_mutex_lock(&connlock);
			g_tree_foreach(ext_tree1, (GTraverseFunc) expire_conn,
					GINT_TO_POINTER(delay));

			g_tree_foreach(int_tree2, (GTraverseFunc) expire_conn,
					GINT_TO_POINTER(delay));

			g_tree_foreach(intra_tree1, (GTraverseFunc) expire_conn,
					GINT_TO_POINTER(delay));

			// remove each key listed from the btree
			g_ptr_array_foreach(entrytoclean, (GFunc) remove_conn,
					GINT_TO_POINTER(delay));
			g_mutex_unlock(&connlock);

			// free the array */
			g_ptr_array_free(entrytoclean, TRUE);
			entrytoclean = NULL;

			if (threading == OK) {
				goto rewind;
			}
		}
	}
	g_mutex_unlock(&threading_cond_lock);

}

/*! setup_redirection
 \brief called for each connection being redirected to setup and start the redirection process
 \param[in] conn: redirected connection metadata
 \return OK when done, NOK in case of failure
 */
status_t setup_redirection(struct conn_struct *conn, uint64_t hih_use) {
	/* Check if decision engine gave me wrong HIH ID */
	if (hih_use == 0) {
		printdbg(
				"%s [** Error, decision engine failed to specify which HIH to use**]\n", H(conn->id));
		return NOK;
	}

	printdbg("%s [** Starting... **]\n", H(conn->id));
	struct handler *back_handler = g_tree_lookup(conn->target->back_handlers,
			&hih_use);

	if (back_handler->ip) {

		ip_addr_t tmp1 = conn->first_pkt_src_ip.addr_ip;
		//ip_addr_t tmp2 = conn->first_pkt_dst_ip.addr_ip;

		// Exclusive HIH, only one attacker is allowed to interact with it at a time
		if (exclusive_hih == 1) {
			struct pin_key *pin_key1 = g_malloc0(sizeof(struct pin_key));
			pin_key1->vlan_id = back_handler->vlan.vid;
			pin_key1->handler_ip = back_handler->ip->addr_ip;

			struct pin *pin = g_tree_lookup(target_pin_tree, &pin_key1->key);
			if (pin) {
				if (pin->ip.addr_ip != conn->first_pkt_dst_ip.addr_ip) {
					// This HIH is pinned to a different target IP
					printdbg(
							"%s Can't setup redirection. HIH is pinned to another target IP \n", H(conn->id));

					free(pin_key1);
					return NOK;
				} else {
					pin->count++;
					conn->hih.target_pin_key = pin_key1;
				}
			} else {
				//printdbg(
				//		"%s Inserting target pin %s to %"PRIx128"\n", H(conn->id), pin_key1, tmp2);

				pin = malloc(sizeof(struct pin));
				pin->pin_key = pin_key1;
				pin->count = 1;
				pin->ip = conn->first_pkt_dst_ip;

				conn->hih.target_pin_key = g_memdup(pin->pin_key,
						sizeof(struct pin_key));

				g_tree_insert(target_pin_tree, pin->pin_key, pin);

			}
		}

		GTimeVal t;
		g_get_current_time(&t);
		gdouble microtime = 0.0;
		microtime += ((gdouble) t.tv_sec);
		microtime += (((gdouble) t.tv_usec) / 1000000.0);

		conn->hih.hihID = hih_use;
		conn->hih.back_handler = back_handler;
		conn->hih.port = conn->first_pkt_dst_port;
		/*! We then update the status of the connection structure */
		conn->stat_time[DECISION] = microtime;

		conn->hih.redirected_int_key = g_malloc0(sizeof(struct conn_key));
		conn->hih.redirected_int_key->protocol = conn->protocol;
		conn->hih.redirected_int_key->vlan_id = back_handler->vlan.vid;
		conn->hih.redirected_int_key->src_ip = back_handler->ip->addr_ip;
		conn->hih.redirected_int_key->src_port = conn->hih.port;
		conn->hih.redirected_int_key->dst_ip = tmp1;
		conn->hih.redirected_int_key->dst_port = conn->first_pkt_src_port;

		//printdbg(
		//		"%s Inserting redirected conn key to ext_tree2: %" PRIx64 "\n", H(conn->id), conn->hih.redirected_int_key->key);

		g_tree_insert(ext_tree2, conn->hih.redirected_int_key, conn);

		switch_state(conn, REPLAY);

		/*! We reset the LIH */
		reset_lih(conn);

		/*! We replay the first packets */
		struct pkt_struct* current;
		current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
				conn->replay_id);

		printdbg("%s [** starting the forwarding loop... **]\n", H(conn->id));

		while (current && current->origin == EXT) {

			forward_ext2hih(current);

			conn->replay_id++;
			current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
					conn->replay_id);
		}

		printdbg("%s [** ...done with the forwarding loop **]\n", H(conn->id));

		if (current) {
			printdbg("%s [** defining expected data **]\n", H(conn->id));
			define_expected_data(current);
			conn->replay_id++;
		}

		return OK;

	} else {
		printdbg("%s [** Error, no HIH address defined **]\n", H(conn->id));
		return NOK;
	}
}

status_t switch_conn_to_intra(struct conn_struct *conn,
		struct handler *intra_handler) {

	conn->intra_handler = intra_handler;

	conn->intra_key = g_malloc0(sizeof(struct conn_key));
	conn->intra_key->protocol = conn->protocol;
	conn->intra_key->vlan_id = conn->intra_handler->vlan.vid;
	conn->intra_key->src_ip = conn->intra_handler->ip->addr_ip;
	conn->intra_key->src_port = conn->first_pkt_dst_port;
	conn->intra_key->dst_ip = conn->first_pkt_src_ip.addr_ip;
	conn->intra_key->dst_port = conn->first_pkt_src_port;

	g_mutex_lock(&connlock);

	// First remove this connection from the int_trees
	g_tree_remove(int_tree1, conn->int_key);
	g_tree_remove(int_tree2, conn->ext_key);

	// And reinsert it into the intra_trees
	g_tree_insert(intra_tree1, conn->int_key, conn);
	g_tree_insert(intra_tree2, conn->intra_key, conn);

	g_mutex_unlock(&connlock);

	return OK;
}

status_t add_conn_to_intra(struct conn_struct *conn,
		struct handler *intra_handler) {

	if (!conn || conn->intra_handler || conn->int_key)
		return NOK;

	conn->intra_handler = intra_handler;

	conn->intra_key = g_malloc0(sizeof(struct conn_key));
	conn->intra_key->protocol = conn->protocol;
	conn->intra_key->vlan_id = intra_handler->vlan.vid;
	conn->intra_key->src_ip = intra_handler->ip->addr_ip;
	conn->intra_key->src_port = conn->first_pkt_dst_port;
	conn->intra_key->dst_ip = conn->first_pkt_src_ip.addr_ip;
	conn->intra_key->dst_port = conn->first_pkt_src_port;

	conn->int_key = g_malloc0(sizeof(struct conn_key));
	conn->int_key->protocol = conn->protocol;
	conn->int_key->vlan_id = conn->first_pkt_vlan.vid;
	conn->int_key->src_ip = conn->first_pkt_src_ip.addr_ip;
	conn->int_key->src_port = conn->first_pkt_src_port;
	conn->int_key->dst_ip = conn->first_pkt_dst_ip.addr_ip;
	conn->int_key->dst_port = conn->first_pkt_dst_port;

#ifdef HONEYBRID_DEBUG
	PRINT_CONN_KEYS(g_printerr,
			"%s Inserting new conn from HIH to intra trees with keys "CONN_KEY_FORMAT" and "CONN_KEY_FORMAT"\n",
			H(conn->id), conn->int_key, conn->intra_key);
#endif

	g_mutex_lock(&connlock);
	g_tree_insert(intra_tree1, conn->int_key, conn);
	g_tree_insert(intra_tree2, conn->intra_key, conn);
	g_mutex_unlock(&connlock);

	return OK;
}
