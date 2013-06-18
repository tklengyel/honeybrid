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

/*! \file netcode.c
 \brief Network functions file

 \author Julien Vehent, 2007
 \author Thomas Coquelin, 2008
 \author Tamas K Lengyel, 2013

 */

#include "netcode.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#include "globals.h"
#include "convenience.h"
#include "log.h"
#include "connections.h"

/*! ip_checksum
 \brief IP checksum using in_cksum
 */
#define ip_checksum(hdr) \
	((struct iphdr*)hdr)->check = \
		in_cksum(hdr, \
		sizeof(struct iphdr))

/*! udp_checksum
 \brief UDP checksum using in_cksum
 */
#define udp_checksum(hdr) \
	((struct udp_packet *)hdr)->udp.check = \
		in_cksum( hdr, \
        sizeof(struct udphdr))

/*! in_cksum
 \brief Checksum routine for Internet Protocol family headers
 \param[in] addr a pointer to the data
 \param[in] len the 32 bits data size
 \return sum a 16 bits checksum
 */
static inline uint16_t in_cksum(const void *addr, uint32_t len) {
    uint32_t sum = 0;
    const uint16_t *w = addr;
    int nleft = len;

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
        uint16_t tmp = 0;
        *(uint8_t *) (&tmp) = *(uint8_t *) w;
        sum += tmp;
    }

    /*! add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /*! add hi 16 to low 16 */
    sum += (sum >> 16); /*! add carry */
    return ((uint16_t) ~sum); /*! truncate to 16 bits */
}

// from http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap/send_arp.c
void set_iface_info(struct interface *iface) {

    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len = strlen(iface->name);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, iface->name, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    } else {
        fprintf(stderr, "interface name is too long");
        exit(1);
    }

    // Open an IPv4-family socket for use when calling ioctl.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror(0);
        exit(1);
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror(0);
        close(fd);
        exit(1);
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*) &ifr.ifr_addr;
    iface->ip=g_malloc0(sizeof(struct addr));
    addr_pack(iface->ip, ADDR_TYPE_IP, 0, &(source_ip_addr->sin_addr.s_addr), sizeof(uint32_t));

    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror(0);
        close(fd);
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        fprintf(stderr, "%s is not an Ethernet interface!\n", iface->name);
        close(fd);
        exit(1);
    }
    close(fd);

    iface->mac = g_malloc0(sizeof(struct addr));
    addr_pack(iface->mac, ADDR_TYPE_ETH, 0, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

void send_arp_reply(struct interface *iface, const u_char *packet) {

    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *request= (struct ether_arp *)(packet + ETHER_HDR_LEN);

    // Construct Ethernet header.
    struct ether_header header;
    header.ether_type = htons(ETH_P_ARP);
    memcpy(&header.ether_shost, &iface->mac->addr_eth, sizeof(header.ether_shost));
    memcpy(&header.ether_dhost, &request->arp_sha, sizeof(header.ether_dhost));

    // Construct ARP reply
    struct ether_arp reply;
    reply.arp_hrd = htons(ARPHRD_ETHER);
    reply.arp_pro = htons(ETH_P_IP);
    reply.arp_hln = ETHER_ADDR_LEN;
    reply.arp_pln = sizeof(in_addr_t);
    reply.arp_op = htons(ARPOP_REPLY);
    memcpy(&reply.arp_sha, &iface->mac->addr_eth, sizeof(reply.arp_sha));

    // Copy IP into ARP reply.
    memcpy(&reply.arp_spa, &request->arp_tpa, sizeof(reply.arp_spa));
    memcpy(&reply.arp_tpa, &request->arp_spa, sizeof(reply.arp_tpa));

    // Combine the Ethernet header and ARP request into a contiguous block.
    unsigned char frame[ETHER_HDR_LEN + sizeof(struct ether_arp)];
    memcpy(frame, &header, ETHER_HDR_LEN);
    memcpy(frame + ETHER_HDR_LEN, &reply, sizeof(struct ether_arp));

    // Write the Ethernet frame to the interface.
    if (pcap_inject(iface->pcap, frame, sizeof(frame)) == -1) {
        printdbg("%s ARP reply injection failed!\n", H(5));
    } else {
        printdbg("%s Sent ARP reply!\n", H(5));
    }
}

/*!
 * tcp checksum function
 \param[in] pkt: packet to compute the checksum
 \return OK
 */
static inline
void tcp_checksum(struct tcp_packet* pkt) {

    //int padd = (pkt->ip.tot_len) & 1;

    struct tcp_chk_packet chk_p;
    bzero(&chk_p, sizeof(struct tcp_chk_packet));

    unsigned short TOT_SIZE = ntohs(pkt->ip.tot_len);
    unsigned short IPHDR_SIZE = (pkt->ip.ihl << 2);
    unsigned short TCPHDRDATA_SIZE = TOT_SIZE - IPHDR_SIZE;
    unsigned short len_tcp = TCPHDRDATA_SIZE;

    if (len_tcp - sizeof(struct tcphdr) >= BUFSIZE)
        printdbg(
                "%s TCP data is greater then our buffer size! %lu > %i!\n", H(0), len_tcp - sizeof(struct tcphdr), BUFSIZE);

    chk_p.pseudohdr.saddr = pkt->ip.saddr;
    chk_p.pseudohdr.daddr = pkt->ip.daddr;
    chk_p.pseudohdr.proto = IPPROTO_TCP;
    chk_p.pseudohdr.tcp_len = htons(len_tcp);

    memcpy(&chk_p.tcp, &pkt->tcp, sizeof(struct tcphdr));
    memcpy(&chk_p.payload, &pkt->payload, len_tcp - sizeof(struct tcphdr));
    chk_p.tcp.check = 0x00; // checksum field has to be zeroed before checksum

    pkt->tcp.check = in_cksum(&chk_p, sizeof(struct pseudotcphdr) + len_tcp);

    printdbg("%s TCP checksum set to 0x%x\n", H(21), pkt->tcp.check);
}

/*
 * This will replace the TCP Timestamps option with TCPOPT_EOL
 * but if there are no other options this TCP segment should be removed
 * and the data offset (doff) updated accordingly (TODO)
 *
 * BEWARE: RIGHT NOW THIS CAN BE USED TO DETECT THE PRESENCE HONEYBRID
 * Only matters if the LIH is configured not to send TS and the HIH is sending TS
 *
 */
static inline
void strip_tcp_timestamps(struct tcphdr *th) {

    if (th->doff == sizeof(struct tcphdr) >> 2) {
        return;
    }

    if (th->doff == (sizeof(struct tcphdr) >> 2) + (TCPOLEN_TSTAMP_APPA >> 2)) {
        unsigned int *ptr = (unsigned int *) (th + 1);
        if (*ptr == ntohl(TCPOPT_TSTAMP_HDR)) {
            *(unsigned char *) ptr = TCPOPT_EOL;
            return;
        }
    }

    // In case there are other optional headers we need to parse normally
    unsigned char *ptr = (unsigned char *) (th + 1);
    unsigned char *length = ptr + (th->doff * 4) - sizeof(struct tcphdr) - 1;

    while (ptr < length) {
        int opcode = ptr[0];
        int opsize = ptr[1];

        switch (opcode) {
            case TCPOPT_EOL:
                return;
            case TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
                ptr++;
                continue;
            case TCPOPT_TIMESTAMP:
                ptr[0] = TCPOPT_EOL;
                return;
            default:
                ptr += opsize;
                break;
        };
    }
}

static inline status_t get_tcp_timestamps(const struct tcphdr* th,
        uint32_t *tsval, uint32_t *tsecho) {

    if (th->doff == sizeof(struct tcphdr) >> 2) {
        return NOK;
    }

    if (th->doff == (sizeof(struct tcphdr) >> 2) + (TCPOLEN_TSTAMP_APPA >> 2)) {
        unsigned int *ptr = (unsigned int *) (th + 1);
        if (*ptr == ntohl(TCPOPT_TSTAMP_HDR)) {

            ++ptr;

            if (tsval)
                *tsval = ntohl(ptr[0]);
            if (tsecho)
                *tsecho = ntohl(ptr[1]);

            printdbg(
                    "%s TCP timestamps found. TSVal: %u TSEcho: %u \n", H(31), ntohl(ptr[0]), ntohl(ptr[1]));

            return OK;
        }
    }

    // In case there are other optional headers we need to parse normally
    unsigned char *ptr = (unsigned char *) (th + 1);
    unsigned char *length = ptr + (th->doff * 4) - sizeof(struct tcphdr) - 1;

    while (ptr < length) {
        int opcode = ptr[0];
        int opsize = ptr[1];

        switch (opcode) {
            case TCPOPT_EOL:
                return NOK;
            case TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
                ptr++;
                continue;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {

                    unsigned int *ts = (unsigned int *) (ptr + 2);

                    if (tsval)
                        *tsval = ntohl(ts[0]);
                    if (tsecho)
                        *tsecho = ntohl(ts[1]);

                    printdbg(
                            "%s TCP timestamps found. TSVal: %u. TSEcho: %u\n", H(31), ntohl(ts[0]), ntohl(ts[1]));

                    return OK;
                }
                break;
            default:
                ptr += opsize;
                break;
        };
    }

    return NOK;
}

static inline
void set_tcp_timestamps(struct tcphdr* th, uint32_t *tsval, uint32_t *tsecho) {

    if (th->doff == sizeof(struct tcphdr) >> 2 || (!tsval && !tsecho)) {
        return;
    }

    if (th->doff == (sizeof(struct tcphdr) >> 2) + (TCPOLEN_TSTAMP_APPA >> 2)) {
        unsigned int *ptr = (unsigned int *) (th + 1);
        if (*ptr == ntohl(TCPOPT_TSTAMP_HDR)) {

            ++ptr;

            if (tsval)
                ptr[0] = htonl(*tsval);
            if (tsecho)
                ptr[1] = htonl(*tsecho);

            return;
        }
    }

    // In case there are other optional headers we need to parse normally
    unsigned char *ptr = (unsigned char *) (th + 1);
    unsigned char *length = ptr + (th->doff * 4) - sizeof(struct tcphdr) - 1;

    while (ptr < length) {
        int opcode = ptr[0];
        int opsize = ptr[1];

        switch (opcode) {
            case TCPOPT_EOL:
                return;
            case TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
                ptr++;
                continue;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {

                    unsigned int *ts = (unsigned int *) (ptr + 2);

                    if (tsval)
                        ts[0] = htonl(*tsval);
                    if (tsecho)
                        ts[1] = htonl(*tsecho);

                    return;
                }
                break;
            default:
                ptr += opsize;
                break;
        };
    }
}

static inline status_t fix_tcp_timestamps(struct tcphdr* th,
        const struct conn_struct *conn) {
    if (conn->replay_problem & REPLAY_UNEXPECTED_TCP_TS) {
        strip_tcp_timestamps(th);

        printdbg("%s TCP timestamps stripped. This is detectable!\n", H(21));

        return OK;
    }
    if (conn->replay_problem & REPLAY_TCP_TS_OUTOFSYNC) {

        uint32_t tcp_ts;
        if (OK == get_tcp_timestamps(th, &tcp_ts, NULL)) {
            tcp_ts = (int) tcp_ts + (int) conn->tcp_ts_diff;
            set_tcp_timestamps(th, &tcp_ts, NULL);

            printdbg("%s Updated TCP timestamp to %u!\n", H(21), tcp_ts);

            return OK;
        }
    }
    if (conn->replay_problem & REPLAY_EXPECTED_TCP_TS) {
        //TODO
        printdbg(
                "%s Was expecting TCP timestamps but didn't find them. This is detectable!\n", H(21));
    }

    return NOK;
}

/*! send_raw
 \brief send a packet over a raw socket
 \param[in] p, the packet structure that contains the packet to be sent
 \return OK if the packet has been succesfully sent
 */

status_t send_raw(const struct iphdr *p, const struct interface *iface) {

#ifdef DEBUG
    struct tcphdr *test = (struct tcphdr*) (((char *) p) + (p->ihl << 2));
    printdbg(
            "%s sending packet in raw socket: %s:%d -> ", H(4), inet_ntoa(*(struct in_addr *) &p->saddr), ntohs(test->source));
    printdbg(
            "%s:%d\n", inet_ntoa(*(struct in_addr *) &p->daddr), ntohs(test->dest));
#endif

    struct sockaddr_in dst;
    bzero(&dst, sizeof(struct sockaddr_in));
    int bytes_sent;
    int sockettouse = 0;
    dst.sin_addr.s_addr = p->daddr;
    dst.sin_family = AF_INET;

    if (!iface) {
        if (p->protocol == IPPROTO_TCP)
            sockettouse = tcp_rsd;
        else if (p->protocol == IPPROTO_UDP)
            sockettouse = udp_rsd;
        else
            return NOK;
    } else {
        if (p->protocol == IPPROTO_TCP)
            sockettouse = iface->tcp_socket;
        else if (p->protocol == IPPROTO_UDP)
            sockettouse = iface->udp_socket;
        else
            return NOK;
    }

    bytes_sent = sendto(sockettouse, p, ntohs(p->tot_len), 0,
            (__CONST_SOCKADDR_ARG) &dst, sizeof(struct sockaddr_in));

    if (bytes_sent < 0) {
        printdbg("%s Packet not sent\n", H(4));
        return NOK;
    } else {
        printdbg(
                "%s Packet of size %u sent on socket %i to %s, total of %u bytes\n", H(4), ntohs(p->tot_len), sockettouse, inet_ntoa(dst.sin_addr), bytes_sent);
        return OK;
    }
}

/*! proxy
 *
 \brief proxy the packet to it's destination
 \param[in] pkt, the packet metadata structure to forward

 \return OK if the packet has been succesfully sent
 */
status_t proxy(struct pkt_struct* pkt) {

    //TODO: NAT

    printdbg("%s Sending PROXY packet on %s\n", H(6), pkt->out->tag);

    if (pkt->out && pcap_inject(pkt->out->pcap, pkt->packet.eth, pkt->size) != -1) {
        return OK;
    }

    return NOK;
}

/*! forward
 *
 \brief forward the packet to the attacker or to the HIH according to its origin
 \param[in] pkt, the packet metadata structure to forward

 \return OK if the packet has been succesfully sent
 */

status_t forward_hih(struct pkt_struct* pkt) {
    printdbg("%s forwarding packet to EXT\n", H(pkt->conn->id));

    struct iphdr * ip = (struct iphdr *) pkt->packet.ip;

    /*!We set LIH source IP*/
    ip->saddr = pkt->conn->hih.lih_addr;

    /*!If TCP, we update the source port, the sequence number, and the checksum*/
    if (ip->protocol == IPPROTO_TCP) {

        struct tcp_packet* tcp_fwd = (struct tcp_packet*) pkt->packet.tcppacket;

        tcp_fwd->tcp.source = pkt->conn->hih.port;
        tcp_fwd->tcp.seq = htonl(
                ntohl(pkt->packet.tcp->seq) + pkt->conn->hih.delta);
        fix_tcp_timestamps(&tcp_fwd->tcp, pkt->conn);
        tcp_checksum(tcp_fwd);
    }
    /*!If UDP, we update the source port and the checksum*/
    else if (ip->protocol == IPPROTO_UDP) //udp
    {
        ((struct udp_packet*) pkt->packet.udppacket)->udp.source =
                pkt->conn->hih.port;
        udp_checksum(pkt->packet.udppacket);
    }

    ip_checksum(ip);


    if(pcap_inject(pkt->out->pcap, pkt->packet.eth, pkt->size) == (int)pkt->size) {
        return OK;
    }

    return NOK;
}

status_t forward_ext(struct pkt_struct* pkt) {

    struct iphdr * ip = (struct iphdr *) pkt->packet.ip;

    printdbg(
            "%s forwarding packet to HIH %u\n", H(pkt->conn->id), pkt->conn->hih.hihID);

    ip = (struct iphdr *) pkt->packet.ip;
    ip->daddr = pkt->conn->hih.addr;

    /*!If TCP, we update the destination port, the acknowledgement number if any, and the checksum*/
    if (ip->protocol == IPPROTO_TCP) {

        struct tcp_packet* tcp_fwd = (struct tcp_packet*) pkt->packet.tcppacket;

        tcp_fwd->tcp.dest = pkt->conn->hih.port;
        if (tcp_fwd->tcp.ack == 1) {
            tcp_fwd->tcp.ack_seq = htonl(
                    ntohl(pkt->packet.tcp->ack_seq)
                    + ~(pkt->conn->hih.delta) + 1);
        }
        tcp_checksum(tcp_fwd);
    }
    /*!If UDP, we update the destination port and the checksum*/
    else if (ip->protocol == IPPROTO_UDP) {
        ((struct udp_packet*) pkt->packet.udppacket)->udp.dest =
                pkt->conn->hih.port;
        udp_checksum(pkt->packet.udppacket);
    }

    struct interface *iface = pkt->conn->hih.iface;

    ip_checksum(ip);

    if (pcap_inject(iface->pcap, pkt->packet.eth, pkt->size)
            == (int)pkt->size) {
        return OK;
    }

    return NOK;
}

/*! reply_reset
 *
 \brief creat a RST packet from a unexepcted packet and sends it with send_raw
 \param[in] p, the packet to which we reply the reset packet

 */

void reply_reset(struct pkt_struct *pkt, struct interface *iface) {

    if (pkt && iface) {

        status_t res;
        struct tcp_packet rst;
        bzero(&rst, sizeof(struct tcp_packet));

        /*! fill up the IP header */
        rst.ip.version = 4;
        rst.ip.ihl = sizeof(struct iphdr) >> 2;
        rst.ip.tot_len = ntohs(sizeof(struct iphdr) + sizeof(struct tcphdr));
        rst.ip.frag_off = ntohs(0x4000);
        rst.ip.ttl = 0x40;
        rst.ip.protocol = IPPROTO_TCP;
        //rst.ip.check = 0x00;
        rst.ip.saddr = pkt->packet.ip->daddr;
        rst.ip.daddr = pkt->packet.ip->saddr;
        ip_checksum(&rst);

        /*! fill up the TCP header */
        rst.tcp.source = pkt->packet.tcp->dest;
        rst.tcp.dest = pkt->packet.tcp->source;
        if (pkt->packet.tcp->ack == 1)
            rst.tcp.seq = (pkt->packet.tcp->ack_seq);
        rst.tcp.ack_seq =
                htonl(
                        ntohl(pkt->packet.tcp->seq) + pkt->packet.tcp->syn +pkt->packet.tcp->fin
                        + ntohs(pkt->packet.ip->tot_len) - (pkt->packet.ip->ihl << 2)
                        - (pkt->packet.tcp->doff << 2));
        rst.tcp.doff = 0x5;
        rst.tcp.rst = 0x1;
        rst.tcp.ack = 0x1;
        tcp_checksum(&rst);

        pcap_inject(iface->pcap, &rst, pkt->size);
    }
}

/*! reset_lih
 *
 \brief reset the LIH when redirected to HIH
 \param[in] conn: the connnection that the LIH reset
 */

void reset_lih(struct conn_struct* conn) {

    //! reset only tcp connections
    if (conn->protocol != IPPROTO_TCP)
        return;

    struct packet *p = NULL;
    struct pkt_struct* tmp;
    printdbg("%s Reseting LIH\n", H(conn->id));

    GSList * current = (GSList *) conn->BUFFER;
    do {
        tmp = (struct pkt_struct*) g_slist_nth_data(current, 0);
        if (tmp->origin == LIH)
            p = &tmp->packet;
    } while ((current = g_slist_next(current)) != NULL);

    if (p == NULL || p->ip == NULL) {
        printdbg("%s no packet found from LIH\n", H(conn->id));
    } else {
        reply_reset(tmp, tmp->conn->target->front_handler->iface);
    }
}

/*! replay
 *
 \brief reset the LIH when redirected to HIH
 \param[in] conn: the connnection being replayed
 \param[in] pkt: the packet from HIH to test

 */

status_t replay(struct conn_struct* conn, struct pkt_struct* pkt) {
    status_t ret = NOK;
    int de = 0;
    struct pkt_struct* current = NULL;

    printdbg("%s Replay called\n", H(conn->id));

    if (pkt->origin != HIH)
        goto done;

    /*
     *  If packet is from HIH and matches expected data
     * then we replay the following packets from EXT to HIH
     * until we find a packet from LIH
     */
    if (test_expected(conn, pkt) == OK) {

        printdbg("%s Looping over BUFFER\n", H(conn->id));
        current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
                conn->replay_id);
        de = current->DE;
        while (current->origin == EXT || de == 1) {
            printdbg("%s --(Origin: %d)\n", H(conn->id), current->origin);

            if (current->origin == EXT)
                forward_ext(current);

            if (g_slist_next(g_slist_nth( conn->BUFFER, conn->replay_id ))
                    == NULL) {

                switch_state(conn, FORWARD);

                ret = OK;
                goto done;
            }

            conn->replay_id++;
            current = (struct pkt_struct*) g_slist_nth_data(conn->BUFFER,
                    conn->replay_id);

            if (de == 0) {
                de = current->DE;
            }
        }
        printdbg("%s Defining expected data\n", H(conn->id));
        /*!Then we define expected data according to that packet*/
        define_expected_data(current);
        //g_rw_lock_writer_lock( &conn->lock );
        conn->replay_id++;
        //g_rw_lock_writer_unlock( &conn->lock );
    }

    ret = OK;

    done: return ret;
}

/*! define_expected_data
 *
 \brief define expected packet from HIH according to the packet from LIH
 \param[in] pkt: packet metadata used

 */
void define_expected_data(struct pkt_struct* pkt) {
    pkt->conn->expected_data.ip_proto = pkt->packet.ip->protocol;
    pkt->conn->expected_data.payload = pkt->packet.payload;
    if (pkt->packet.ip->protocol == IPPROTO_TCP) {
        pkt->conn->expected_data.tcp_seq = ntohl(pkt->packet.tcp->seq)
                + ~pkt->conn->hih.delta + 1;
        pkt->conn->expected_data.tcp_ack_seq = ntohl(pkt->packet.tcp->ack_seq);

        uint32_t temp;
        if (OK == get_tcp_timestamps(pkt->packet.tcp, &temp, NULL)) {
            pkt->conn->expected_data.tcp_ts = (int64_t) temp;
        } else {
            pkt->conn->expected_data.tcp_ts = -1;
        }

    }
}

/*! test_expected
 *
 \brief get the packet from HIH, compare it to expected data, drop it and return the comparison result
 */
status_t test_expected(struct conn_struct* conn, struct pkt_struct* pkt) {
    status_t flag = OK;

    if (pkt->packet.ip->protocol != conn->expected_data.ip_proto) {
        printdbg(
                "%s Unexpected protocol: %d\n", H(conn->id), pkt->packet.ip->protocol);

        conn->replay_problem |= REPLAY_UNEXPECTED_PROTOCOL;

        flag = NOK;
        goto test_done;
    }

    if (pkt->packet.ip->protocol == IPPROTO_TCP) {
        if (pkt->packet.tcp->syn == 0
                && (ntohl(pkt->packet.tcp->seq) != conn->expected_data.tcp_seq)) {

            printdbg(
                    "%s Unexpected TCP seq. number: %u. Expected: %u\n", H(conn->id), ntohl(pkt->packet.tcp->seq), conn->expected_data.tcp_seq);

            conn->replay_problem |= REPLAY_UNEXPECTED_TCP_SEQ;

            flag = NOK;
            goto test_done;
        }

        if (ntohl(pkt->packet.tcp->ack_seq)
                != conn->expected_data.tcp_ack_seq) {

            printdbg("%s Unexpected TCP ack. number\n", H(conn->id));

            conn->replay_problem |= REPLAY_UNEXPECTED_TCP_ACK;

            flag = NOK;
            goto test_done;
        }

        /*
         * Test TCP Timestamps. These problems can be handled.
         */
        int64_t tcp_ts = -1;
        uint32_t temp;
        if (OK == get_tcp_timestamps(pkt->packet.tcp, &temp, NULL)) {
            tcp_ts = (int64_t) temp;
        }

        if (conn->expected_data.tcp_ts == -1 && tcp_ts != -1) {
            printdbg(
                    "%s Unexpected TCP Timestamp (will be stripped)\n", H(conn->id));

            conn->replay_problem |= REPLAY_UNEXPECTED_TCP_TS;

        } else if (conn->expected_data.tcp_ts > -1 && tcp_ts > -1
                && tcp_ts != conn->expected_data.tcp_ts) {

            conn->tcp_ts_diff = conn->expected_data.tcp_ts - tcp_ts;
            conn->replay_problem |= REPLAY_TCP_TS_OUTOFSYNC;

            printdbg(
                    "%s TCP Timestamp is smaller then expected (will be updated). Skew: %li.\n", H(conn->id), conn->tcp_ts_diff);

        } else if (conn->expected_data.tcp_ts > -1 && tcp_ts == -1) {
            printdbg(
                    "%s TCP Timestamp was expected (should be added)\n", H(conn->id));

            conn->replay_problem |= REPLAY_EXPECTED_TCP_TS;
        }
    }

    if (!strncmp(pkt->packet.payload, conn->expected_data.payload, pkt->data)
            == 0) {
        printdbg("%s Unexpected payload\n", H(conn->id));
        conn->replay_problem = conn->replay_problem | REPLAY_UNEXPECTED_PAYLOAD;
    }

    if (flag == OK)
        printdbg("%s Expected data OK\n", H(conn->id));

    test_done: return flag;
}
