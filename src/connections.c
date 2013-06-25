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
    pkt->size = header->caplen;
    pkt->in = iface;

    /*! Assign the packet IP header and payload to the packet structure */
    if (ethertype == ETHERTYPE_IP) {

        /* Save the packet with enough room to add a VLAN header if needed */
        pkt->packet.FRAME = malloc(pkt->size + VLAN_HLEN);
        memcpy(pkt->packet.FRAME + VLAN_HLEN, packet, pkt->size);
        pkt->packet.eth = (struct ether_header *) (pkt->packet.FRAME + VLAN_HLEN);

        pkt->original_headers.eth = g_memdup(pkt->packet.eth, ETHER_HDR_LEN);
        pkt->packet.ip = (struct iphdr *) ((char *)pkt->packet.eth + ETHER_HDR_LEN);
    } else if (ethertype == ETHERTYPE_VLAN) {

        pkt->packet.FRAME = malloc(pkt->size);
        memcpy(pkt->packet.FRAME, packet, pkt->size);
        pkt->packet.vlan = (struct vlan_ethhdr *) (pkt->packet.FRAME);

        pkt->original_headers.vlan = g_memdup(pkt->packet.vlan, VLAN_ETH_HLEN);
        pkt->packet.ip = (struct iphdr *) ((char *)pkt->packet.vlan + VLAN_ETH_HLEN);
    }

    pkt->original_headers.ip = g_memdup(pkt->packet.ip, (pkt->packet.ip->ihl << 2));

    pkt->packet.tcp = (struct tcphdr*) (((char *) pkt->packet.ip)
            + (pkt->packet.ip->ihl << 2));

    char tmp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(pkt->packet.ip->saddr), tmp, INET_ADDRSTRLEN);
    pkt->src = g_strdup(tmp);

    inet_ntop(AF_INET, &(pkt->packet.ip->daddr), tmp, INET_ADDRSTRLEN);
    pkt->dst = g_strdup(tmp);

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

        pkt->original_headers.tcp = g_memdup(pkt->packet.tcp, sizeof(struct tcphdr));

        pkt->packet.payload = (char*) pkt->packet.tcp
                + (pkt->packet.tcp->doff << 2);

        pkt->src_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->src,
                        ntohs(pkt->packet.tcp->source)) + 1);
        sprintf(pkt->src_with_port, "%s:%d", pkt->src,
                ntohs(pkt->packet.tcp->source));

        pkt->dst_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->dst,
                        ntohs(pkt->packet.tcp->dest)) + 1);
        sprintf(pkt->dst_with_port, "%s:%d", pkt->dst,
                ntohs(pkt->packet.tcp->dest));

        /* The volume of data is the total size of the packet minus the size of the IP and TCP headers */
        pkt->data = ntohs(pkt->packet.ip->tot_len) - (pkt->packet.ip->ihl << 2)
                - (pkt->packet.tcp->doff << 2);

    } else if (pkt->packet.ip->protocol == IPPROTO_UDP) {

        pkt->original_headers.udp = g_memdup(pkt->packet.udp, sizeof(struct udphdr));

        pkt->packet.payload = (char*) pkt->packet.udp + UDP_HDR_LEN;
        /*! Process UDP packet */
        pkt->src_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->src,
                        ntohs(pkt->packet.udp->source)) + 1);
        sprintf(pkt->src_with_port, "%s:%u", pkt->src,
                ntohs(pkt->packet.udp->source));
        pkt->dst_with_port = g_malloc0(
                snprintf(NULL, 0, "%s:%d", pkt->dst,
                        ntohs(pkt->packet.udp->dest)) + 1);
        sprintf(pkt->dst_with_port, "%s:%u", pkt->dst,
                ntohs(pkt->packet.udp->dest));

        /* The volume of data is the value of udp->ulen minus the size of the UPD header (always 8 bytes) */
        pkt->data = pkt->packet.udp->len - UDP_HDR_LEN;
    } else {
        printdbg("%s Invalid protocol, packet skipped\n", H(4));

        goto done;
    }

    if (pkt->data < 0) {
        printdbg("%s Invalid data size: %d, packet skipped\n", H(4), pkt->data);

        goto done;
    }

    // Check if the packet comes from a target interface
    if (pkt->in->target) {
        pkt->origin = EXT;

        addr_pack(&pkt->keys.ip, ADDR_TYPE_IP, 0, &pkt->packet.ip->saddr,
                sizeof(ip_addr_t));

        if (pkt->packet.ip->protocol == IPPROTO_TCP) {
            pkt->keys.port = pkt->packet.tcp->source;
        } else if (pkt->packet.ip->protocol == IPPROTO_UDP) {
            pkt->keys.port = pkt->packet.udp->source;
        }
    } else {
        // Packet came from an interface that's not assigned as a target default route
        // That means it's an internal honeynet interface, so packet is either from LIH or HIH
        // but we don't know which (yet)
        pkt->origin = INT;

        addr_pack(&pkt->keys.ip, ADDR_TYPE_IP, 0, &pkt->packet.ip->daddr,
                sizeof(ip_addr_t));

        if (pkt->packet.ip->protocol == IPPROTO_TCP) {
            pkt->keys.port = pkt->packet.tcp->dest;
        } else if (pkt->packet.ip->protocol == IPPROTO_UDP) {
            pkt->keys.port = pkt->packet.udp->dest;
        }
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
    g_free(pkt->original_headers.eth);
    g_free(pkt->original_headers.vlan);
    g_free(pkt->original_headers.ip);
    g_free(pkt->original_headers.tcp);
    g_free(pkt->original_headers.udp);
    g_free(pkt->packet.FRAME);
    g_free(pkt->src);
    g_free(pkt->dst);
    g_free(pkt->src_with_port);
    g_free(pkt->dst_with_port);
    g_free(pkt);
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

status_t switch_state(struct conn_struct *conn, conn_status_t new_state) {

    printdbg(
            "%s switching state from %s to %s\n",
            H(conn->id), lookup_state(conn->state), lookup_state(new_state));

    conn->state = new_state;

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
 == g_tree_lookup_extended(conn_tree, key, NULL,
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

int conn_lookup(struct pkt_struct *pkt, struct attacker_pin **pin,
        struct conn_struct **conn) {

    int ret = 0;
    *conn = NULL;
    *pin = NULL;

    g_mutex_lock(&connlock);

    printdbg(
            "%s Looking for connection %s%s <-> %s%s!\n",
            H(0), pkt->src_with_port, pkt->in->target?" (TARGET)":"",
            pkt->dst_with_port, pkt->in->target?"":" (TARGET)");

    /* Check first if the attacker is pinned to a target already */
    if (TRUE
            == g_tree_lookup_extended(conn_tree, &pkt->keys.ip, NULL,
                    (gpointer *) pin)) {

        // Attacker is pinned to a target

        // Let's see if this packet is of the right target if its coming from EXT
        if (pkt->origin == EXT && (*pin)->target->default_route != pkt->in) {
            printdbg(
                    "%s Attacker %s is attacking multiple targets which is currently not supported. Skipping.", H(3), pkt->src_with_port);
            ret = -1;
            goto done;
        } else if (TRUE
                == g_tree_lookup_extended((*pin)->port_tree, &pkt->keys.port,
                        NULL, (gpointer *) conn)) {

            if (pkt->packet.ip->protocol != (*conn)->protocol) {
                printdbg(
                        "%s This connection is supposed to be %s but packet is %s. Skipping (TODO?)", H(3), lookup_proto((*conn)->protocol), lookup_proto(pkt->packet.ip->protocol));
                ret = -1;
                goto done;
            }

            g_mutex_lock(&(*conn)->lock);

            // Connection found, update origin if it's still unknown internal
            if (pkt->origin == INT) {
                if (pkt->packet.ip->saddr==(*conn)->target->front_handler->ip->addr_ip) {
                    // If it matches the front handler's IP, its LIH
                    pkt->origin = LIH;
                } else {
                    // If its not from the front handler, it must be one of the back handlers
                    pkt->origin = HIH;
                }
            }

            ret = 1;
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

    done:
    g_mutex_unlock(&connlock);

    return ret;
}

status_t create_conn(struct pkt_struct *pkt, struct attacker_pin *pin,
        struct conn_struct **conn, gdouble microtime) {

    status_t result = NOK;

    /*! The key could not be found, so we need to figure out where this packet comes from */
    if (pkt->packet.ip->protocol == IPPROTO_TCP && pkt->packet.tcp->syn == 0) {

        printdbg(
                "%s ~~~~ TCP packet without SYN: we skip %s -> %s~~~~\n", H(0), pkt->src_with_port, pkt->dst_with_port);
        return result;
    }

    struct target *target = NULL;

    g_mutex_lock(&connlock);

    if (pkt->origin == EXT) {
        target = g_hash_table_lookup(targets, pkt->in->tag);
        goto conn_init;
    }

    // We need to loop the targets to find the Honeypot where this packet came from

    char tmp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->packet.ip->saddr, tmp, INET_ADDRSTRLEN);

    char *target_if;
    GHashTableIter i;
    ghashtable_foreach(targets, i, target_if, target) {
        if (pkt->packet.ip->saddr==target->front_handler->ip->addr_ip) {
            printdbg(
                    "%s This packet matches a LIH honeypot IP address of target with default route %s\n", H(0), target->default_route->tag);
            pkt->origin = LIH;
            goto conn_init;
        }

        printdbg("%s Looking for HIH %s\n", H(0), tmp);

        if (g_tree_lookup(target->unique_backend_ips, &tmp) != NULL) {
            printdbg(
                    "%s This packet matches a HIH honeypot IP address of target with default route %s\n", H(0), target->default_route->tag);
            pkt->origin = HIH;
            goto conn_init;
        }
    }

    /*! this packet is for an unconfigured target, we drop it */
    printdbg(
            "%s No honeypot IP found for this address: %s. Skipping for now.\n", H(0), pkt->dst);
    goto done;

    /*! initialize connection */
    conn_init:
    printdbg("%s Initializing connection structure\n", H(5));

    /*! Init new connection structure */
    struct conn_struct *conn_init = (struct conn_struct *) g_malloc0(
            sizeof(struct conn_struct));

    g_mutex_init(&conn_init->lock);
    g_mutex_lock(&conn_init->lock);

    /*! fill the structure */
    conn_init->target = target;
    conn_init->keys = pkt->keys;
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
        conn_init->first_pkt_src_port = pkt->packet.tcp->source;
        conn_init->first_pkt_dst_port = pkt->packet.tcp->dest;
    } else {
        conn_init->first_pkt_src_port = pkt->packet.udp->source;
        conn_init->first_pkt_dst_port = pkt->packet.udp->dest;
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

    /*! Pin this attacker to the target */
    if (!pin) {
        pin = g_malloc0(sizeof(struct attacker_pin));

        pin->ip = conn_init->keys.ip;
        pin->target = conn_init->target;
        pin->port_tree = g_tree_new((GCompareFunc) intcmp);

        g_tree_insert(conn_tree, &pin->ip, pin);

        printdbg(
                "%s Created new attacker pin entry to target with default route %s\n", H(0), conn_init->target->default_route->name);
    }

    g_tree_insert(pin->port_tree, &conn_init->keys.port, conn_init);

    printdbg(
            "%s Connection inserted to attacker's port_tree with key %u\n", H(0), conn_init->keys.port);

    /*! store new entry in current struct */
    pkt->conn = conn_init;
    *conn = conn_init;

    result = OK;

    done: g_mutex_unlock(&connlock);
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
    switch (pkt->origin) {
        case EXT:
            conn->count_data_pkt_from_intruder += 1;

            // Take the VLAN from the packet (if any) IFF we don't have one set yet
            if (pkt->original_headers.vlan) {
                if (!conn->uplink_vlan.vid) {
                    conn->uplink_vlan = pkt->original_headers.vlan->h_vlan_TCI;
                } else if (conn->uplink_vlan.vid
                        != pkt->original_headers.vlan->h_vlan_TCI.vid) {
                    printdbg(
                            "%s Packet VLAN (%u) doesn't match uplink mark previously set on connection (%u)!\n",
                            H(conn->id), pkt->original_headers.vlan->h_vlan_TCI.vid, conn->uplink_vlan.vid);
                }
            }
            break;
        default:
            // Take the VLAN from the packet (if any) IFF we don't have one set yet
            if (pkt->original_headers.vlan) {
                if (!conn->downlink_vlan.vid) {
                    conn->downlink_vlan =
                            pkt->original_headers.vlan->h_vlan_TCI;
                } else if (conn->downlink_vlan.vid
                        != pkt->original_headers.vlan->h_vlan_TCI.vid) {
                    printdbg(
                            "%s Packet mark (%u) doesn't match uplink mark previously set on connection (%u)!\n",
                            H(conn->id), pkt->original_headers.vlan->h_vlan_TCI.vid, conn->uplink_vlan.vid);
                }
            }
            break;
    }

    pkt->conn = conn;
    return OK;
}

void remove_conn(struct expire_conn *expire,
        __attribute__ ((unused)) gpointer data) {

    if (!expire->delay) {
        // This connection must expire
        g_mutex_lock(&expire->conn->lock);
    } else if (FALSE == g_mutex_trylock(&expire->conn->lock)) {
        return;
    }

    struct attacker_pin *pin = (struct attacker_pin *) g_tree_lookup(conn_tree,
            expire->key_ip);

    g_tree_remove(pin->port_tree, &expire->key_port);

    if (g_tree_nnodes(pin->port_tree) == 0) {
        g_tree_remove(conn_tree, expire->key_ip);
        free_attacker_pin(pin);
    }

    connection_log(expire->conn);
    free_conn(expire->conn);
}

gboolean expire_conn_port(uint16_t *port, struct conn_struct *conn,
        struct expire_conn_port *input) {

    GTimeVal t;
    g_get_current_time(&t);
    int curtime = (t.tv_sec);
    int delay = GPOINTER_TO_INT(input->delay);

    if ((curtime - conn->access_time > delay || conn->state < INIT)) {

        printdbg(
                "%s called with expiration delay on connection %u: %d\n", H(8), conn->id, delay);

        struct expire_conn *expire = g_malloc0(sizeof(struct expire_conn));

        expire->conn = conn;
        expire->key_port = *port;
        expire->key_ip = input->key_ip;
        expire->delay = delay;

        g_ptr_array_add(entrytoclean, expire);

    }

    return FALSE;
}

gboolean expire_conn(struct addr *ip, struct attacker_pin *pin, gpointer delay) {

    struct expire_conn_port expire = { .delay = delay, .key_ip = ip };

    g_tree_foreach(pin->port_tree, (GTraverseFunc) expire_conn_port, &expire);

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

    struct attacker_pin *pin = NULL;

    switch (conn_lookup(pkt, &pin, conn)) {
        case 0:
            return create_conn(pkt, pin, conn, microtime);
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

        printdbg("%s Connection %u entry removed\n", H(8), conn->id);

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
        g_mutex_clear(&conn->lock);
        g_free(conn->hih.redirect_key);
        g_string_free(conn->start_timestamp, TRUE);
        g_string_free(conn->decision_rule, TRUE);
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
            entrytoclean = g_ptr_array_new_with_free_func(g_free);

            /*! call the clean function for each value */
            g_mutex_lock(&connlock);
            g_tree_foreach(conn_tree, (GTraverseFunc) expire_conn,
                    GINT_TO_POINTER(delay));

            /*! remove each key listed from the btree */
            g_ptr_array_foreach(entrytoclean, (GFunc) remove_conn, NULL);
            g_mutex_unlock(&connlock);

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
        printdbg(
                "%s [** Error, decision engine failed to specify which HIH to use**]\n", H(conn->id));
        return NOK;
    }

    printdbg("%s [** Starting... **]\n", H(conn->id));
    struct handler *back_handler = g_tree_lookup(conn->target->back_handlers,
            &hih_use);

    if (back_handler->ip) {

        /*GHashTable *hih_redir_list = NULL;

         g_rw_lock_writer_lock(&hihredirlock);

         if ((hih_redir_list = g_hash_table_lookup(high_redirection_table,
         conn->key)) == NULL) {
         if (NULL
         == (links = g_hash_table_new_full(g_str_hash, g_str_equal,
         g_free, NULL))) errx(1,
         "%s: Fatal error while creating nested redirection hash table.\n",
         __func__);
         }

         g_hash_table_insert(hih_redir_list, g_strdup(conn->key_with_port),
         GUINT_TO_POINTER(TRUE));

         g_hash_table_insert(high_redirection_table, g_strdup(conn->key),
         hih_redir_list);

         printdbg(
         "%s [** high_redirection_table updated: key %s value %s **]\n", H(conn->id), conn->key, conn->key_with_port);

         g_rw_lock_writer_unlock(&hihredirlock);*/

        GTimeVal t;
        g_get_current_time(&t);
        gdouble microtime = 0.0;
        microtime += ((gdouble) t.tv_sec);
        microtime += (((gdouble) t.tv_usec) / 1000000.0);

        conn->hih.hihID = hih_use;
        conn->hih.iface = back_handler->iface;
        conn->hih.ip = back_handler->ip;
        conn->hih.mac = back_handler->mac;
        conn->hih.port = conn->first_pkt_dst_port;
        /*! We then update the status of the connection structure */
        conn->stat_time[DECISION] = microtime;

        switch_state(conn, REPLAY);

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
