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

#ifndef _TYPES_H_
#define _TYPES_H_

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <dumbnet.h>
#include "modules.h"

#define ETHER_ADDR_LEN	6
#define ETHER_HDR_LEN	14

/*!
 \def target
 \brief structure to hold target information: PCAP filter and rules to accept/forward/redirect/control packets
 */

struct target
{
	struct bpf_program *filter;	/* PCAP compiled filter to select packets for this target */
	struct addr *front_handler;	/* Honeypot IP address(es) handling the first response (front end) */
	struct node *front_rule;	/* Rules of decision modules to accept packet to be handled by the frontend */
	struct addr *back_handler;		/* Honeypot IP address(es) handling the second response (back end) */
	struct node *back_rule;		/* Rules of decision modules to accept packets to be transited from front to back end */
	struct node *control_rule;	/* Rules of decision modules to limit outbound packets from honeypots */
};


/*!
 \def ethernet_hdr
 \brief memory structure to hold ethernet header (14 bytes)
 */

struct ethernet_hdr {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};


/*!
 \def packet
 *
 \brief The IP packet structure
 *
 \param ip, ip header
 \param payload[BUFSIZE], payload buffer
 *
 */

struct packet
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	char *payload;
	char *FRAME;
};

/*!
 \def tcp_packet
 *
 \brief The TCP/IP packet structure
 *
 \param ip, ip header
 \param tcp, tcp header
 \param payload[BUFSIZE], payload buffer
 *
 */
struct tcp_packet
{
	struct iphdr ip;
	struct tcphdr tcp;
	char *payload;
};

/*!
 \def udp_packet
 *
 \brief The UDP/IP packet structure
 *
 \param ip, ip header
 \param udp, udp header
 \param payload[BUFSIZE], payload buffer
 *
 */
struct udp_packet
{
	struct iphdr ip;
	struct udphdr udp;
	char *payload;
};

/*! hih_struct
 \brief hih info

 \param addr, IP address
 \param port, port
 */
struct hih_struct
{
	int addr;
	short port;
	unsigned lih_syn_seq;
	unsigned delta;
	int lih_addr;
};

/*! expected_data_struct
 \brief expected_data_struct info

 \param ip_proto, expected IP following protocol
 \param tcp_seq, expected TCP sequence number
 \param tcp_seq_ack, expected TCP ack number
 \param payload, expected payload
 */
struct expected_data_struct
{
	unsigned short ip_proto;
	unsigned tcp_seq;
	unsigned tcp_ack_seq;
	char* payload;
};

/*! conn_struct
 \brief The meta informations of a connection stored in the main Binary Tree

 \param key, the tuple (also the b-tree key)
 \param key_ext, the IP and Port of the external attacker
 \param key_lih, the IP and Port of the Low Interaction Honeypot
 \param key_hih, the IP and Port of the High Interaction Honeypot
 \param protocol, the l4 protocol number (6 for TCP, 17 for UDP, ...)
 \param access_time, the last access time
 \param status, the status of the connection: (1) for INIT, (2) for DECISION, (3) for REPLAY and (4) for FORWARD. (0) can mean INVALID
 \param count_data_pkt_from_lih, nb of packet replied from the lih to the intruder
 \param count_data_pkt_from_intruder, nb of packet sent from the intruder to the LIH
 \param BUFFER, pointer to the beginning of the list of the recorded packets (stored through pkt_struct)
 \param lock, set to 1 when a packet is currently processed for this connection
 \param hih, hih info
 */
struct conn_struct
{
	char *key;
	char *key_ext;
	char *key_lih;
	char *key_hih;
	int protocol;
	GString *start_timestamp;
	gdouble start_microtime;
	gint access_time;
	int state;
	unsigned id;
	int replay_id;
	int count_data_pkt_from_lih;
	int count_data_pkt_from_intruder;
	GSList *BUFFER;
	struct expected_data_struct expected_data;
	GStaticRWLock lock;
	struct hih_struct hih;

	struct target *target;

	/* statistics */
	gdouble  stat_time[8]; // = {0,0,0,0,0,0,0};
	int   stat_packet[8]; // = {0,0,0,0,0,0,0};
	int   stat_byte[8]; // = {0,0,0,0,0,0,0};
	int   total_packet;
	int   total_byte;
	int   decision_packet_id;
	///char* decision_rule;
	GString *decision_rule;
	int   replay_problem;
	int   invalid_problem; //unused
};

/*! pkt_struct
 \brief The meta information of a packet stored in the conn_struct connection structure

 \param packet, pointer to the packet
 \param origin, to define from where the packet is coming (EXT, LIH or HIH)
 \param data, to provide the number of bytes in the packet
 \param DE, (0) if the packet was received before the decision to redirect, (1) otherwise
 */
struct pkt_struct
{
	struct packet packet;
	int origin;
	int data;
	int size;
	int DE;
	struct conn_struct * conn;
	char *key_src;
	char *key_dst;
	char *key;
	int position;
};


/*! \brief Structure to pass arguments to the Decision Engine
 \param conn, pointer to the refered conn_struct
 \param packetposition, position of the packet to process in the Singly Linked List
 */
struct DE_submit_args
{
	struct conn_struct *conn;
	int packetposition;
};

#endif
