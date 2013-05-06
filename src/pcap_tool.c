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

/*! \file pcap_tool.c
 \brief Pcap function to record communications

 \Author J. Vehent
 */

#include <sys/time.h>
#include <glib.h>

#include "pcap_tool.h"
#include "tables.h"
#include "log.h"

/*! create_pcap_filename
 *
 \brief create a filename based on the configuration and a time value
 *
 \param[in] mode, 0 for non redirected file name, 1 for redirected file name
 \return a GString structure
 */
GString * create_pcap_filename(int mode) {
	GString *name;
	name = g_string_new("");
	/*! prefix = value from the config file
	 */
	g_string_append_printf(name, "%s",
			(gchar *) g_hash_table_lookup(config, "conn_record"));

	/*! add the current time
	 */
	struct tm *actualtime = NULL;
	time_t t;
	if (time(&t) != (time_t) -1)
		actualtime = localtime(&t);

	g_string_append_printf(name, "%d%d%d-%d-%d-%d",
			(actualtime->tm_year + 1900), (actualtime->tm_mon + 1),
			actualtime->tm_mday, actualtime->tm_hour, actualtime->tm_min,
			actualtime->tm_sec);

	if (mode == 1) {
		g_string_append_printf(name, "-redirected");
	}

	/*! and finally, the '.pcap' extension
	 */
	g_string_append_printf(name, ".pcap");

	/*! return the structure GString created
	 */
	return name;
}

/*! init_pcap_context
 *
 \brief create the pcap descriptors
 *
 \return 0 on success, anything else otherwise
 */
int init_pcap_context() {
	/*! pcap_open_dead, open offline context for pcap
	 \param[in] DLT_RAW, assume incoming packet doesn't have a layer 2 header (netfilter requierement)
	 \param[in] BUFSIZE, max size of a packet
	 \return pcap_main_desc, a descriptor to the pcap context
	 */
	if (NULL == (pcap_main_desc = pcap_open_dead(DLT_RAW, PCAPSIZE))) {
///		L(32,"INIT_PCAP_CONTEXT",NULL,5);

		return -1;
	}

	/*! create output filename based on the conf and the time value */
	GString *output_file_name;
	output_file_name = create_pcap_filename(0);

	/*! pcap_dump_open, create an output file descriptor for this context
	 \param[in] pcap_main_desc, a descriptor to the pcap context
	 \param[in] output_file_name->str, the filename
	 \return pcap_output_current, a pcap file descriptor
	 */
	if (NULL
			== (pcap_output_current = pcap_dump_open(pcap_main_desc,
					output_file_name->str))) {
///		L(33,"INIT_PCAP_CONTEXT",NULL, 5);

		return -1;
	}

///	L(34,"INIT_PCAP_CONTEXT",output_file_name->str, 5);

	/*! create output filename for redirected connections */
	GString *redirected_output_file_name;
	redirected_output_file_name = create_pcap_filename(1);

	/*! same for output of redirected connections
	 */
	if (NULL
			== (pcap_output_redirected = pcap_dump_open(pcap_main_desc,
					redirected_output_file_name->str))) {
///		L(35,"INIT_PCAP_CONTEXT",NULL, 5);

		return -1;
	}
///	L(34,"INIT_PCAP_CONTEXT",redirected_output_file_name->str, 5);

	return 0;
}

/*! record_pkt
 *
 \brief record a packet in the current pcap file descriptor
 *
 \param[in] nfq_data *tb, raw packet ( used with nfqueue)
 \param[in] *payload, packet to record (used outside of nfqueue)
 \param[in] mode, 0 for non redirected connection, 1 for redirected connections, 2 for redirected outside nfqueue, 3 for non redirected outside nfqueue
 *
 \return 0 on success, anything else otherwise
 */
int record_pkt(struct nfq_data *tb, char *p, int mode) {
	/*! if pcap desc doesn't exist, init pcap context
	 */
	if (!pcap_main_desc) {
		if (0 != init_pcap_context())
			return -1;
	}

	pcap_dumper_t *DumpDescriptor;

	/*! switch the descriptor regarding to the mode (redirected or not)
	 */
	if (mode == 0)
		DumpDescriptor = pcap_output_current;
	else
		DumpDescriptor = pcap_output_redirected;

	/*! if the actual pcap output file is bigger than 10mo, create a new one
	 */
	if (ftell((FILE *) DumpDescriptor) > 10485760) {

		/*! close the current descriptor */
		pcap_dump_close(DumpDescriptor);

		/*! create output filename based on the conf and the time value */
		GString *file_name;
		file_name = (GString *) create_pcap_filename(mode);

		/*! open the new file descriptor
		 */
		if (NULL
				== (DumpDescriptor = pcap_dump_open(pcap_main_desc,
						file_name->str))) {
///			L(33,"RECORD_PKT",file_name->str, 5);

			return -1;
		}

///		L(34,"RECORD_PKT",file_name->str,5);

		/*! store new descriptor in global descriptor
		 */
		if ((mode == 0) || (mode == 3))
			pcap_output_current = DumpDescriptor;
		else
			pcap_output_redirected = DumpDescriptor;
	}

	/*! create pcap specific header
	 */
	struct pcap_pkthdr phdr;

	GTimeVal t;
	g_get_current_time(&t);

	phdr.ts.tv_sec = t.tv_sec;
	phdr.ts.tv_usec = t.tv_usec;

	if ((mode == 2) || (mode == 3)) {
		/*! mode 2 and 3 are used when we need to record a packet received outside of
		 * the netfilter queue
		 */
		struct iphdr *ip = (struct iphdr *) p;
		phdr.caplen = ntohs(ip->tot_len); /*! +1 because the '\0' is not included */
		phdr.len = phdr.caplen;

		/*! pcap_dump, write pcap header and packet data to the output file
		 \param[in] pcap_output_current, descriptor to the current output file
		 \param[in] &phdr, pcap header
		 \param[in] payload, packet data
		 */
		pcap_dump((void *) DumpDescriptor, &phdr, (const u_char *) p);
	} else {
		char *netfilter_packet;
		phdr.caplen = nfq_get_payload(tb, &netfilter_packet);
		phdr.len = phdr.caplen;

		/*! pcap_dump, write pcap header and packet data to the output file
		 \param[in] pcap_output_current, descriptor to the current output file
		 \param[in] &phdr, pcap header
		 \param[in] (const u_char *)nf_packet, packet data from netfilter queue
		 */
		pcap_dump((void *) DumpDescriptor, &phdr,
				(const u_char *) netfilter_packet);
	}
///	L(36,"RECORD_PKT",NULL, 5);

	return 0;
}

/*! close_pcap_context, close the descriptors
 \param[in]
 \return 0 on success, anything else otherwise
 */
int close_pcap_context() {
	pcap_dump_close(pcap_output_current);
	pcap_dump_close(pcap_output_redirected);
	pcap_close(pcap_main_desc);

	return 0;
}
