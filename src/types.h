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

#ifndef _TYPES_H_
#define _TYPES_H_

#include <config.h>

// Include standard headers
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

// Include network headers
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <dumbnet.h>
#include <glib.h>

/*!
 \def PAYLOADSIZE
 * use by NF_QUEUE to set the data size of received packets
 */
#define PAYLOADSIZE     0xffff

/*!
 \def BUFSIZE
 *
 * number of bytes in the payload we want to copy to userspace
 * a regular ethernet connection limit payload size to 1500 bytes
 */
#define BUFSIZE 2048

#define MIN_PACKET_SIZE 42 // Ethernet(14) + IPv4(20) + UDP(8)

#define MIN_UDP_SIZE MIN_PACKET_SIZE

#define MIN_TCP_SIZE 54 // Ethernet(14) + IPv4(20) + TCP(20)

/*! \brief constants to define the origin of a packet
 */
typedef enum {
    EXT,
    INT,
    LIH,
    HIH,

    __MAX_ORIGIN
} origin_t;

/*! \brief constants to define the status of a connection
 */
typedef enum {
    INVALID,
    INIT,
    DECISION,
    REPLAY,
    FORWARD,
    PROXY,
    DROP,
    CONTROL,

    __MAX_CONN_STATUS
} conn_status_t;

typedef enum {
    DNAT_LIH,
    DNAT_HIH,
    SNAT
} nat_t;

/*! \brief output modes
 */
typedef enum {
    OUTPUT_INVALID,
    OUTPUT_SYSLOG,
    OUTPUT_STDOUT,
    OUTPUT_LOGFILES,
    OUTPUT_MYSQL
} output_t;

typedef enum {
	NOK = -1,
	OK = 1
} status_t;

typedef enum {
	REPLAY_UNEXPECTED_PROTOCOL 	= (1 << 0),
	REPLAY_UNEXPECTED_PAYLOAD	= (1 << 1),
	REPLAY_UNEXPECTED_TCP_ACK	= (1 << 2),
	REPLAY_UNEXPECTED_TCP_SEQ 	= (1 << 3),
	REPLAY_UNEXPECTED_TCP_TS 	= (1 << 4),
	REPLAY_EXPECTED_TCP_TS		= (1 << 5),
	REPLAY_TCP_TS_OUTOFSYNC		= (1 << 6)
} replay_problem_t;

/*!
 \def decision types
 */
typedef enum {
	DE_NO_RULE,
	DE_DEFER,
	DE_REJECT,
	DE_ACCEPT
} decision_t;

typedef enum {
	DEFER = DE_DEFER,
	REJECT = DE_REJECT,
	ACCEPT = DE_ACCEPT
} mod_result_t;

/*!
 \def verbosity channel
 1 errors only
 2 minimal redirection information
 3 full redirection information
 4 internal processing events
 5 permanent internal processing events
 */
typedef enum {
	LOG_MIN,
	LOG_LOW,
	LOG_MED,
	LOG_HIGH,
	LOG_ALL
} log_verbosity_t;

/*!
 \def log identifiers
 * log id values:
 1 -> main
 2 -> signal handlers
 3 -> config parse
 4 -> unkown connection
 5 -> pcap tools
 6 -> modules
 7 -> log
 8 -> clean engine
 9 -> honeypot queries
 */
typedef enum {
	LOG_MISC,
	LOG_MAIN,
	LOG_SIGNAL,
	LOG_CONFIG,
	LOG_UNKNOWN,
	LOG_PCAP,
	LOG_MODULES,
	LOG_LOG,
	LOG_CLEAN,
	LOG_HONEYPOT
} log_id_t;

struct mod_args;
typedef mod_result_t (*module_function)(struct mod_args *);

#endif
