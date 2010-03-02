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

#ifndef _PCAP_TOOL_H_
#define _PCAP_TOOL_H_

#include <pcap.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/*!
 \def pcap_record
 *
 * Pcap recording mode, set to 1 if pcap recording is activated
 */
int pcap_record;


/*!
  \def PCAPSIZE
 *
 * max size of a packet in PCAP
 */
#define PCAPSIZE 2048

/*!
 \def pcap_main_desc
 *
 * Main descriptor for the pcap context
 */
pcap_t *pcap_main_desc;


/*!
 \def pcap_output_current
 *
 * Current pcap file descriptor to write the packets
 */
pcap_dumper_t *pcap_output_current;

/*!
 \def pcap_output_redirected
 *
 * Pcap file descriptor for recording redirected connections
 */
pcap_dumper_t *pcap_output_redirected;

int record_pkt(struct nfq_data *tb, char *p, int mode);

int close_pcap_context();

#endif //_PCAP_TOOL_H_
