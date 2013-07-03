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

/*! \file mod_control_dns.c
 * \brief Control module to redirect all DNS queries to an internal host on-the-fly
 *          This module should only be placed in the "limit" section of a target configuration.
 *          Every subsequent connections to this IP will be redirected to the INTRA target
 *
 \author Tamas K Lengyel 2013
 */

#include "modules.h"

//DNS header structure
struct dns_header {
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct question {
    unsigned short qtype;
    unsigned short qclass;
};

mod_result_t mod_dns_control(struct mod_args *args) {

    mod_result_t result = ACCEPT;

    if (args->pkt == NULL || args->pkt->conn->destination != EXT) {
        goto done;
    }

    printdbg("%s Module called\n", H(args->pkt->conn->id));

    if ((args->pkt->packet.ip->protocol == IPPROTO_TCP
            && ntohs(args->pkt->packet.tcp->dest) != 53)
            || (args->pkt->packet.ip->protocol == IPPROTO_UDP
                    && ntohs(args->pkt->packet.udp->dest) != 53)
            || args->pkt->data < sizeof(struct dns_header)) {

        // It's not DNS
        goto done;
    }

    struct dns_header *dns = (struct dns_header *) args->pkt->packet.payload;

    if (dns && dns->qr == 0 && dns->q_count > 0 && ntohs(dns->opcode) < 6) {
        // It looks like a DNS query
        printdbg(
                "%s DNS query ID %u OPCODE %u with %u questions\n", H(args->pkt->conn->id), ntohs(dns->id), ntohs(dns->opcode), ntohs(dns->q_count));

#ifdef HONEYBRID_DEBUG
        uint32_t qcount = 1;
        char *query = (char *) dns + sizeof(struct dns_header);
        struct question *question = (struct question *) ((char*) dns
                + strlen(query) + 1);
        while (qcount <= (ntohs(dns->q_count))) {
            printdbg(
                    "%s DNS query type %u for %s\n", H(args->pkt->conn->id), ntohs(question->qtype), query);
            query += strlen(query) + 1 + sizeof(struct question);
            qcount++;
        }
#endif

        // We will switch the query to our internal DNS server
        char *our_server_iface = g_hash_table_lookup(args->node->config,
                "interface");
        char *our_server_ip = g_hash_table_lookup(args->node->config, "ip");
        char *our_server_mac = g_hash_table_lookup(args->node->config, "mac");
        int *vlan = g_hash_table_lookup(args->node->config, "vlan_id");

        if (!our_server_iface || !our_server_ip || !our_server_mac || !vlan) {
            // Incomplete configuration
            goto done;
        }

        switch_state(args->pkt->conn, PROXY);
        args->pkt->conn->destination = INTRA;

        struct addr *target_ip = g_malloc(sizeof(struct addr));
        addr_pack(target_ip, ADDR_TYPE_IP, 32, &args->pkt->packet.ip->daddr,
                sizeof(ip_addr_t));

        // Check if we have an internal handler defined for this target IP
        struct handler *intra_handler = g_tree_lookup(args->pkt->conn->target->intra_handlers, target_ip);
        if (!intra_handler) {
            struct addr *ip = g_malloc0(sizeof(struct addr));
            addr_pton(our_server_ip, ip);

            struct addr *mac = g_malloc0(sizeof(struct addr));
            addr_pton(our_server_mac, mac);

            intra_handler = g_malloc0(sizeof(struct handler));
            intra_handler->iface = g_hash_table_lookup(links, our_server_iface);
            intra_handler->intra_target_ip = target_ip;
            intra_handler->ip = ip;
            intra_handler->ip_str = g_strdup(our_server_ip);
            intra_handler->mac = mac;
            intra_handler->vlan.i = htons(*vlan & ((1 << 12)-1));
            intra_handler->exclusive = 0; // allow this inra to act as multiple target IPs
                                          // since this is a DNS server, we don't expect it to initiate reverse connections

            g_mutex_lock(&args->pkt->conn->target->lock);
            g_tree_insert(args->pkt->conn->target->intra_handlers,
                    intra_handler->intra_target_ip, intra_handler);
            g_mutex_unlock(&args->pkt->conn->target->lock);
        } else {
            free(target_ip);
        }

        args->pkt->conn->intra_handler = intra_handler;

        args->pkt->conn->intra_key = g_malloc0(
                snprintf(NULL, 0, "%u:%s:%s:%s:%u",
                        args->pkt->packet.ip->protocol,
                        args->pkt->conn->intra_handler->ip_str,
                        args->pkt->dst_port, args->pkt->src_with_port,
                        args->pkt->conn->intra_handler->vlan.vid) + 1);
        sprintf(args->pkt->conn->intra_key, "%u:%s:%s:%s:%u",
                args->pkt->packet.ip->protocol,
                args->pkt->conn->intra_handler->ip_str, args->pkt->dst_port,
                args->pkt->src_with_port,
                args->pkt->conn->intra_handler->vlan.vid);

        g_mutex_lock(&connlock);

        // First remove this connection from the int_trees
        g_tree_steal(int_tree1, args->pkt->conn->int_key);
        g_tree_steal(int_tree2, args->pkt->conn->ext_key);

        // And reinsert it into the intra_trees
        g_tree_insert(intra_tree1, args->pkt->conn->int_key, args->pkt->conn);
        g_tree_insert(intra_tree2, args->pkt->conn->intra_key, args->pkt->conn);

        g_mutex_unlock(&connlock);

        result = ACCEPT;

    }

    done: return result;
}

