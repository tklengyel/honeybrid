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
    pkt->size = header->len;
    pkt->in = iface;

    /* Save the packet */
    pkt->packet.FRAME = malloc(pkt->size);
    memcpy(pkt->packet.FRAME, packet, pkt->size);

    pkt->packet.eth = (struct ether_header *) pkt->packet.FRAME;

    /*! Assign the packet IP header and payload to the packet structure */
    if (ethertype == ETHERTYPE_IP) {
        pkt->packet.ip = (struct iphdr *) (pkt->packet.FRAME + ETHER_HDR_LEN);
    } else if (ethertype == ETHERTYPE_VLAN) {
        pkt->vlan_in = pkt->packet.vlan_eth->h_vlan_TCI;
        pkt->packet.ip = (struct iphdr *) (pkt->packet.FRAME + VLAN_ETH_HLEN);
    }

    pkt->packet.tcp = (struct tcphdr*) (((char *) pkt->packet.ip)
            + (pkt->packet.ip->ihl << 2));

    char tmp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(pkt->packet.ip->saddr), tmp, INET_ADDRSTRLEN);
    pkt->key_src = g_strdup(tmp);

    inet_ntop(AF_INET, &(pkt->packet.ip->daddr), tmp, INET_ADDRSTRLEN);
    pkt->key_dst = g_strdup(tmp);

    if (pkt->packet.ip->protocol == IPPROTO_TCP) {
        /*! Process TCP packets */

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

        pkt->packet.payload = (char*) pkt->packet.tcp
                + (pkt->packet.tcp->doff << 2);

        /*! key_src_with_port is the tuple with the source information
         * {Source IP}:{Source Port} */
        pkt->key_src_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->key_src,
                        ntohs(pkt->packet.tcp->source)) + 1);
        sprintf(pkt->key_src_with_port, "%s:%d", pkt->key_src,
                ntohs(pkt->packet.tcp->source));

        /*! key_dst_with_port is the one with the destination information
         * {Dest IP}:{Dest Port} */
        pkt->key_dst_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->key_dst,
                        ntohs(pkt->packet.tcp->dest)) + 1);
        sprintf(pkt->key_dst_with_port, "%s:%d", pkt->key_dst,
                ntohs(pkt->packet.tcp->dest));

        /* The volume of data is the total size of the packet minus the size of the IP and TCP headers */
        pkt->data = ntohs(pkt->packet.ip->tot_len) - (pkt->packet.ip->ihl << 2)
                - (pkt->packet.tcp->doff << 2);

    } else if (pkt->packet.ip->protocol == IPPROTO_UDP) {
        pkt->packet.payload = (char*) pkt->packet.udp + UDP_HDR_LEN;
        /*! Process UDP packet */
        /*! key_src */
        pkt->key_src_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->key_src,
                        ntohs(pkt->packet.udp->source)) + 1);
        sprintf(pkt->key_src_with_port, "%s:%u", pkt->key_src,
                ntohs(pkt->packet.udp->source));
        /*! key_dst */
        pkt->key_dst_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->key_dst,
                        ntohs(pkt->packet.udp->dest)) + 1);
        sprintf(pkt->key_dst_with_port, "%s:%u", pkt->key_dst,
                ntohs(pkt->packet.udp->dest));
        /* The volume of data is the value of udp->ulen minus the size of the UPD header (always 8 bytes) */
        pkt->data = pkt->packet.udp->len - UDP_HDR_LEN;
    } else{
        printdbg("%s Invalid protocol, packet skipped\n", H(4));

        goto done;
    }

    if (pkt->data < 0) {
        printdbg("%s Invalid data size: %d, packet skipped\n", H(4), pkt->data);

        goto done;
    }

    // Check if the packet comes from a target interface
    if (g_hash_table_lookup(targets, pkt->in->tag)) {
        pkt->origin = EXT;
        pkt->key = pkt->key_src;
        pkt->key_with_port = pkt->key_src_with_port;
    } else {
        // Packet came from an interface that's not assigned as a target default route
        // That means it's an internal honeynet interface, so packet is either from LIH or HIH
        // but we don't know which (yet)
        pkt->origin = INT;
        pkt->key = pkt->key_dst;
        pkt->key_with_port = pkt->key_dst_with_port;
    }

    printdbg("%s Packet is from %s. Keys: %s %s\n", H(4), lookup_origin(pkt->origin), pkt->key, pkt->key_with_port);

    ret = OK;

    done: if (ret == NOK) {
        free(pkt);
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
    if (pkt != NULL) {
        g_free(pkt->packet.FRAME);
        g_free(pkt->key_src);
        g_free(pkt->key_dst);
        g_free(pkt->key_src_with_port);
        g_free(pkt->key_dst_with_port);
//        g_free(pkt->key);
//        g_free(pkt->key_with_port);
        g_free(pkt);
    }
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

    if (ret == OK)
    printdbg(
            "%s\t Packet stored in memory for connection %s\n", H(conn->id), conn->key);

    return ret;
}

status_t init_mark(struct pkt_struct *pkt, const struct conn_struct *conn) {
    status_t ret = OK;

    switch (pkt->origin) {
        case HIH:
            if (conn->uplink_vlan) pkt->vlan = conn->uplink_vlan;
            break;
        case EXT:
            if (conn->downlink_vlan) pkt->vlan = conn->downlink_vlan;
            break;
        case LIH:
        default:
            ret = NOK;
            break;
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
        if (i == 7) printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8) printf(" ");

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
        if (isprint(*ch)) printf("%c", *ch);
        else printf(".");
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

    if (len <= 0) return;

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

status_t switch_state(struct conn_struct *conn, int new_state) {
    int old = conn->state;
    conn->state = new_state;

    printdbg(
            "%s switching state from %s (%d) to %s (%d)\n", H(conn->id), lookup_state(old), old, lookup_state(new_state), new_state);

    return OK;
}

/*! check_pre_dnat_routing
 \brief checking if the packet is a response for a connection initiated from a hih (required for clone routing)
 \param[in] pkt: the packet
 \param[in/out] conn: pointer to a *conn_struct, updated if the corresponding conn is found
 \param[in] uplink_ip: the uplink ip to check for
 \return: NOK on error, OK otherwise
 */
/*status_t check_pre_dnat_routing(struct pkt_struct *pkt,
 struct conn_struct **conn, const char *uplink_ip) {

 char **split = g_strsplit(pkt->key_dst, ":", 0);

 if (!strcmp(split[0], uplink_ip)) {
 // uplink match, let's see if connection originally came from one of the HIHs

 uint32_t i;
 for (i = 0; i < targets->len; i++) {
 struct target *t = g_ptr_array_index(targets,i);

 const char *ip = NULL;
 char *key = NULL;
 struct backend *back_handler = NULL;
 GHashTableIter i;
 ghashtable_foreach(t->unique_backend_ips, &i, &ip, &back_handler)
 {

 key = g_malloc0(
 snprintf(NULL, 0, "%s:%s:%s", pkt->key_src, ip,
 split[1]) + 1);

 sprintf(key, "%s:%s:%s", pkt->key_src, ip, split[1]);

 if (TRUE
 == g_tree_lookup_extended(flow_tree, key, NULL,
 (gpointer *) conn)
 && (*conn)->initiator == HIH) {
 printdbg(
 "Connection initiated from backend found with mark: %u\n", (*conn)->downlink_vlan);

 pkt->key = key;

 break;
 } else {
 free(key);
 }
 }
 }
 }

 g_strfreev(split);
 return OK;
 }*/

status_t conn_lookup(struct pkt_struct *pkt, struct conn_struct **conn) {

    status_t ret = OK;
    *conn = NULL;

    g_rw_lock_reader_lock(&connlock);

    printdbg(
            "%s Looking for connection %s <-> %s with key %s!\n", H(0), pkt->key_src_with_port, pkt->key_dst_with_port, pkt->key_with_port);

    /* Check first if a structure already exists */
    if (FALSE
            == g_tree_lookup_extended(flow_tree, pkt->key_with_port, NULL,
                    (gpointer *) conn)) {
        char *value = NULL;

        /* Nothing found, looking up in the redirection table */
        g_rw_lock_reader_lock(&hihredirlock);
        value = g_hash_table_lookup(high_redirection_table, pkt->key);
        g_rw_lock_reader_unlock(&hihredirlock);

        if (value != NULL) {
            printdbg(
                    "%s ~~~~ This packet is part of a replayed connection ~~~~~\n", H(0));

            pkt->origin = HIH;

            if (FALSE
                    == g_tree_lookup_extended(flow_tree, pkt->key, NULL,
                            (gpointer *) conn)) {
                printdbg(
                        "%s ~~~~ Error! Related connection structure can't be found with key %s ~~~~~\n", H(0), pkt->key);
                ret = NOK;
            }
        }
    } else {
        // Connection found, update origin if its still unknown internal
        if (pkt->origin == INT) {
            if(pkt->in == (*conn)->target->front_handler->iface) {
                pkt->origin = LIH;
            } else {
                pkt->origin = HIH;
            }
        }
    }

    g_rw_lock_reader_unlock(&connlock);

    if (ret == OK && *conn && pkt->packet.ip->protocol == IPPROTO_TCP) {
        // Both sides sent TCP-FIN already
        // We need to expire this connection and start a new one.
        if ((*conn)->tcp_fin_in && (*conn)->tcp_fin_out
                && !tcp_ack_only(pkt->packet.tcp)) {

            printdbg("%s Expiring TCP connection manually.\n", H((*conn)->id));
            gint expire = 0;

            g_rw_lock_writer_lock(&connlock);
            expire_conn(pkt->key, *conn, &expire);
            g_rw_lock_writer_unlock(&connlock);

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
    }

    done: return ret;
}

status_t create_conn(struct pkt_struct *pkt, struct conn_struct **conn,
        gdouble microtime) {

    status_t result = NOK;

    /*! The key could not be found, so we need to figure out where this packet comes from */
    if (pkt->packet.ip->protocol == IPPROTO_TCP && pkt->packet.tcp->syn == 0) {

        printdbg(
                "%s ~~~~ TCP packet without SYN: we skip %s -> %s~~~~\n", H(0), pkt->key_src, pkt->key_dst);
        return result;
    }

    struct target *target = NULL;

    g_rw_lock_writer_lock(&connlock);

    if (pkt->origin == EXT) {
        target = g_hash_table_lookup(targets, pkt->in->tag);
        goto conn_init;
    }

    // We need to loop the targets to find the Honeypot where this packet came from

    struct addr src_addr;
    char tmp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->packet.ip->saddr, tmp, INET_ADDRSTRLEN);
    addr_pton(tmp, &src_addr);

    char *target_if;
    GHashTableIter i;
    ghashtable_foreach(targets, i, target_if, target) {
        if (addr_cmp(target->front_handler->ip, &src_addr) == 0) {
            printdbg(
                    "%s This packet matches a LIH honeypot IP address of target with default route %s\n", H(0), target->default_route->tag);
            pkt->origin = LIH;
            goto conn_init;
        }

        if (g_hash_table_lookup(target->unique_backend_ips, tmp) != NULL) {
            printdbg(
                    "%s This packet matches a HIH honeypot IP address of target with default route %s\n", H(0), target->default_route->tag);
            pkt->origin = HIH;
            goto conn_init;
        }
    }

    /*! this packet is for an unconfigured target, we drop it */
    printdbg(
            "%s No honeypot IP found for this address (%s), pkt key: %s, skipping for now.\n", H(0), inet_ntoa(*(struct in_addr*) &pkt->packet.ip->daddr), pkt->key);
    goto done;

    /*! initialize connection */
    conn_init:
    printdbg("%s Initializing connection structure\n", H(5));

    /*! Init new connection structure */
    struct conn_struct *conn_init = (struct conn_struct *) g_malloc0(
            sizeof(struct conn_struct));

    g_rw_lock_init(&conn_init->lock);
    g_rw_lock_writer_lock(&conn_init->lock);

    /*! fill the structure */
    conn_init->target = target;
    conn_init->key = g_strdup(pkt->key);
    conn_init->key_with_port = g_strdup(pkt->key_with_port);
    //conn_init->key_ext_with_port = g_strdup(pkt->key_src_with_port);
    //conn_init->key_lih_with_port = g_strdup(pkt->key_dst_with_port);
    conn_init->protocol = pkt->packet.ip->protocol;
    conn_init->access_time = microtime;
    conn_init->initiator = pkt->origin;
    conn_init->id = ++c_id;

    conn_init->tcp_fin_in = FALSE;
    conn_init->tcp_fin_out = FALSE;

    /*! statistics */
    conn_init->start_microtime = microtime;
    conn_init->stat_time[INIT] = microtime;
    conn_init->stat_packet[INIT] = 1;
    conn_init->stat_byte[INIT] = pkt->size;
    conn_init->total_packet = 1;
    conn_init->total_byte = pkt->size;
    conn_init->decision_rule = g_string_new("");

    addr_pack(&conn_init->first_pkt_src_mac, ADDR_TYPE_ETH, 0,
            &pkt->packet.eth->ether_shost, ETH_ALEN);
    addr_pack(&conn_init->first_pkt_dst_mac, ADDR_TYPE_ETH, 0,
            &pkt->packet.eth->ether_dhost, ETH_ALEN);
    addr_pack(&conn_init->first_pkt_src_ip, ADDR_TYPE_IP, 0,
            &pkt->packet.ip->saddr, sizeof(ip_addr_t));
    addr_pack(&conn_init->first_pkt_dst_ip, ADDR_TYPE_IP, 0,
            &pkt->packet.ip->daddr, sizeof(ip_addr_t));

    if (conn_init->protocol == IPPROTO_TCP) {
        conn_init->first_pkt_src_port = ntohs(pkt->packet.tcp->source);
        conn_init->first_pkt_dst_port = ntohs(pkt->packet.tcp->dest);
    } else {
        conn_init->first_pkt_src_port = ntohs(pkt->packet.udp->source);
        conn_init->first_pkt_dst_port = ntohs(pkt->packet.udp->dest);
    }

    if (pkt->origin == EXT) {
        conn_init->state = INIT;
        conn_init->uplink_vlan = pkt->vlan_in;
    } else if (pkt->origin == LIH) {
        conn_init->state = CONTROL;
        conn_init->downlink_vlan = pkt->vlan_in;
    } else if (pkt->origin == HIH) {
        conn_init->state = INIT;
        conn_init->downlink_vlan = pkt->vlan_in;
    }

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

    /*! insert entry in B-Tree */
    g_tree_insert(flow_tree, conn_init->key_with_port, conn_init);

    printdbg(
            "%s Key '%s' inserted to flow_tree with uplink mark %u and downlink mark %u\n", H(0), conn_init->key_with_port, conn_init->uplink_vlan, conn_init->downlink_vlan);

    /*! store new entry in current struct */
    pkt->conn = conn_init;
    *conn = conn_init;

    result = OK;

    done: g_rw_lock_writer_unlock(&connlock);
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

    g_rw_lock_writer_lock(&(conn->lock));
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

        // Take the mark from the packet (if any) IFF we don't have one set yet
        if (pkt->vlan) {
            if (!conn->uplink_vlan) conn->uplink_vlan = pkt->vlan;
            else if (conn->uplink_vlan != pkt->vlan) {
                printdbg(
                        "%s Packet mark (%u) doesn't match uplink mark previously set on connection (%u)!\n", H(conn->id), pkt->vlan, conn->uplink_vlan);
            }
        }

    } else if (pkt->origin == HIH) {
        // Take the mark from the packet (if any) IFF we don't have one set yet
        if (pkt->vlan) {
            if (!conn->downlink_vlan) conn->downlink_vlan = pkt->vlan;
            else if (conn->downlink_vlan != pkt->vlan) {
                printdbg(
                        "%s Packet mark (%u) doesn't match uplink mark previously set on connection (%u)!\n", H(conn->id), pkt->vlan, conn->uplink_vlan);
            }
        }
    }

    pkt->conn = conn;
    return OK;
}

/*! expire_conn
 \brief called for each entry in the B-Tree, if a time value is upper to "expiration_delay" (default is 120 sec) and the connection is not marked as redirected, entry is deleted
 \param[in] key, a pointer to the current B-Tree key value
 \param[in] conn, a pointer to the current B-Tree associated value
 \param[in] expiration_delay
 \return FALSE, to continue to traverse the tree (if TRUE is returned, traversal is stopped)
 */
status_t expire_conn(gpointer key, struct conn_struct *conn,
        gint *expiration_delay) {
    GTimeVal t;
    g_get_current_time(&t);
    gint curtime = (t.tv_sec);

    int delay = *expiration_delay;

    if (NULL != g_tree_lookup(flow_tree, (char *) key)
            && ((curtime - conn->access_time > delay) || conn->state < INIT)) {

        printdbg(
                "%s called with expiration delay on connection %u: %d\n", H(8), conn->id, delay);

        /*! output final statistics about the connection */
        connection_log(conn);

        /*! lock the structure, this will never be unlocked */
        g_rw_lock_writer_lock(&conn->lock);

        /*! list the entry for later removal */
        g_ptr_array_add(entrytoclean, key);

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

    if (OK == conn_lookup(pkt, conn)) {
        if (*conn) return update_conn(pkt, *conn, microtime);
        else return create_conn(pkt, conn, microtime);
    }

    return NOK;
}

/*! free_conn
 \brief called for each entry in the pointer array, each entry is a key that is deleted from the B-Tree
 \param[in] key, a pointer to the current B-Tree key value stored in the pointer table
 \param[in] trash, user data, unused
 */
void free_conn(gpointer key, __attribute__((unused))      gpointer unused) {

    g_rw_lock_writer_lock(&connlock);

    struct conn_struct *conn = (struct conn_struct *) g_tree_lookup(flow_tree,
            key);

    if (conn) {
        g_tree_steal(flow_tree, key);

        // Decrement the related conn reference count
        struct related_conn *related = (struct related_conn *) g_tree_lookup(
                conn_tree, conn->key);
        if (related) {
            related->reference_count--;

            // If this is the last one, free memory
            if (related->reference_count == 0) {
                g_tree_remove(conn_tree, conn->key);
                related = NULL;
            }
        }
    }

    g_rw_lock_writer_unlock(&connlock);

    if (conn) {

        printdbg("%s entry removed - tuple = %s\n", H(8), (char*) key);

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
                if (custom->data && custom->data_free) custom->data_free(
                        custom->data);

                free(custom);
            }

            current = g_slist_next(current);
        }
        g_slist_free(conn->custom_data);

        g_free(conn->key);
        g_free(conn->hih.redirect_key);
        g_string_free(conn->start_timestamp, TRUE);
        g_string_free(conn->decision_rule, TRUE);
        g_rw_lock_clear(&(conn->lock));
        g_free(conn);
    }
}

/*! clean
 \brief watchman for the b_tree, wake up every minute and check every entries
 */
void clean() {

    int delay = ICONFIG("expiration_delay");
    if (delay <= 0) delay = 120;

    gint64 sleep_cycle;

    while (threading == OK) {

        // Wait for timeout or signal
        g_mutex_lock(&threading_cond_lock);
        sleep_cycle = g_get_monotonic_time() + 60 * G_TIME_SPAN_SECOND;
        if (!g_cond_wait_until(&threading_cond, &threading_cond_lock,
                sleep_cycle)) {

            printdbg("%s cleaning\n", H(8));

            /*! init the table*/
            entrytoclean = g_ptr_array_new();

            /*! call the clean function for each value */
            g_rw_lock_reader_lock(&connlock);
            g_tree_foreach(flow_tree, (GTraverseFunc) expire_conn, &delay);
            g_rw_lock_reader_unlock(&connlock);

            /*! remove each key listed from the btree */
            g_ptr_array_foreach(entrytoclean, (GFunc) free_conn, NULL);

            /*! free the array */
            g_ptr_array_free(entrytoclean, TRUE);
            entrytoclean = NULL;
        }

        g_mutex_unlock(&threading_cond_lock);
    }
}

/*! setup_redirection
 \brief called for each connection being redirected to setup and start the redirection process
 \param[in] conn: redirected connection metadata
 \return OK when done, NOK in case of failure
 */
status_t setup_redirection(struct conn_struct *conn, uint32_t hih_use) {
    /* Check if decision engine gave me wrong HIH ID */
    if (hih_use == 0) {
        return NOK;
    }

    printdbg("%s [** Starting... **]\n", H(conn->id));
    struct handler *back_handler = g_tree_lookup(conn->target->back_handlers,
            &hih_use);
    struct interface *hihiface = back_handler->iface;
    struct addr *hihaddr = back_handler->ip;

    if (hihaddr != NULL) {

        printdbg(
                "%s [** HIH address: %s, port: %u **]\n", H(conn->id), addr_ntoa(hihaddr), conn->first_pkt_dst_port);

        /*! we check for concurrent connections using the same HIH_IP:PORT <-> EXT_IP */
        GString *key_hih_ext = g_string_new("");
        g_string_printf(key_hih_ext, "%s:%u:%s", addr_ntoa(hihaddr),
                conn->first_pkt_dst_port, addr_ntoa(&conn->first_pkt_src_ip));

        g_rw_lock_writer_lock(&hihredirlock);
        if (g_hash_table_lookup(high_redirection_table,
                key_hih_ext->str) == NULL) {

            g_hash_table_insert(high_redirection_table,
                    g_strdup(key_hih_ext->str),
                    g_strdup(addr_ntoa(conn->target->front_handler->ip)));
            printdbg(
                    "%s [** high_redirection_table updated: key %s value %s **]\n", H(conn->id), key_hih_ext->str, addr_ntoa(conn->target->front_handler->ip));

        } else {
            g_string_free(key_hih_ext, TRUE);
            printdbg(
                    "%s [** HIH already busy with the same tuple, can't proceed **]\n", H(conn->id));
            return NOK;
        }
        g_rw_lock_writer_unlock(&hihredirlock);

        GTimeVal t;
        g_get_current_time(&t);
        gdouble microtime = 0.0;
        microtime += ((gdouble) t.tv_sec);
        microtime += (((gdouble) t.tv_usec) / 1000000.0);

        conn->hih.hihID = hih_use;
        conn->hih.iface = hihiface;
        conn->hih.addr = hihaddr;
        conn->hih.lih_addr = conn->target->front_handler->ip;
        conn->hih.port = conn->first_pkt_dst_port;
        conn->hih.redirect_key = g_strdup(key_hih_ext->str);
        /*! We then update the status of the connection structure */
        conn->stat_time[DECISION] = microtime;

        switch_state(conn, REPLAY);

        g_string_free(key_hih_ext, TRUE);

        /*! We reset the LIH */
        reset_lih(conn);

        /*! We replay the first packets */
        struct pkt_struct* current;
        current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
                conn->replay_id);

        printdbg("%s [** starting the forwarding loop... **]\n", H(conn->id));

        while (current && current->origin == EXT) {

            forward_ext(current);

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

    return OK;
}
