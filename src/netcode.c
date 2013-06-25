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
#include "constants.h"
#include "convenience.h"
#include "log.h"
#include "connections.h"

/*! ip_checksum
 \brief IP checksum using in_cksum
 */
#define set_ip_checksum(hdr) \
    ((struct iphdr*)hdr)->check = 0; \
	((struct iphdr*)hdr)->check = \
		in_cksum(hdr, \
		sizeof(struct iphdr))

/*! udp_checksum
 \brief UDP checksum using in_cksum
 */
#define set_udp_checksum(hdr) \
    ((struct udp_packet *)hdr)->udp.check = 0; \
	((struct udp_packet *)hdr)->udp.check = \
		in_cksum( hdr, \
        sizeof(struct udphdr))

/*! udp_checksum
 \brief UDP checksum using in_cksum
 */
#define set_tcp_checksum(hdr) \
    ((struct tcp_packet *)hdr)->tcp.check = 0; \
    ((struct tcp_packet *)hdr)->tcp.check = tcp_checksum(hdr)

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
    addr_pack(&iface->ip, ADDR_TYPE_IP, 0, &(source_ip_addr->sin_addr.s_addr),
            sizeof(uint32_t));

    // Obtain the source MAC address, copy into Ethernet header
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

    addr_pack(&iface->mac, ADDR_TYPE_ETH, 0, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

/*
 * Sends ARP reply to all ARP requests with the receiving interface's MAC.
 */
void send_arp_reply(uint16_t ethertype, struct interface *iface, const u_char *packet) {

    //struct ether_header *eth = (struct ether_header *) packet;
    struct ether_arp *request = NULL;
    size_t psize = sizeof(struct ether_arp);

    if(ethertype==ETHERTYPE_IP) {
        request = (struct ether_arp *) (packet + ETHER_HDR_LEN);
        psize += ETHER_HDR_LEN;
    } else {
        request = (struct ether_arp *) (packet + VLAN_ETH_HLEN);
        psize += VLAN_ETH_HLEN;
    }

    // Only reply to ARP requests that don't match our interface's IP
    if (request->ea_hdr.ar_op == htons(ARPOP_REQUEST)) {

        unsigned char frame[psize];
        struct ether_arp *reply = NULL;

        // Construct Ethernet/VLAN header.
        struct ether_header *header = (struct ether_header *) frame;
        if(ethertype==ETHERTYPE_IP) {
            header->ether_type = htons(ETHERTYPE_ARP);
            reply = (struct ether_arp *) (frame + ETHER_HDR_LEN);
        } else {
            header->ether_type = htons(ETHERTYPE_VLAN);
            // copy the vlan-only portion of the header
            memcpy(frame+ETHER_HDR_LEN, packet+ETHER_HDR_LEN, VLAN_HLEN);
            reply = (struct ether_arp *) (frame + VLAN_ETH_HLEN);
        }

        memcpy(&header->ether_shost, &iface->mac.addr_eth,
                sizeof(header->ether_shost));
        memcpy(&header->ether_dhost, &request->arp_sha,
                sizeof(header->ether_dhost));

        // Construct ARP reply
        reply->arp_hrd = htons(ARPHRD_ETHER);
        reply->arp_pro = htons(ETH_P_IP);
        reply->arp_hln = ETHER_ADDR_LEN;
        reply->arp_pln = sizeof(in_addr_t);
        reply->arp_op = htons(ARPOP_REPLY);
        memcpy(&reply->arp_sha, &iface->mac.addr_eth, sizeof(reply->arp_sha));

        // Copy IP into ARP reply.
        memcpy(&reply->arp_spa, &request->arp_tpa, sizeof(reply->arp_spa));
        memcpy(&reply->arp_tpa, &request->arp_spa, sizeof(reply->arp_tpa));

        // Write the Ethernet frame to the interface.
        if (pcap_inject(iface->pcap, frame, sizeof(frame)) == -1) {
            printdbg("%s ARP reply injection failed!\n", H(5));
        } else {
            printdbg("%s Sent ARP reply!\n", H(5));
        }
    }
}

/*!
 * tcp checksum function
 \param[in] pkt: packet to compute the checksum
 \return OK
 */
static inline uint16_t tcp_checksum(struct tcp_packet* pkt) {

    struct tcp_chk_packet chk_p;
    bzero(&chk_p, sizeof(struct tcp_chk_packet));

    unsigned short TOT_SIZE = ntohs(pkt->ip.tot_len);
    unsigned short IPHDR_SIZE = (pkt->ip.ihl << 2);
    unsigned short TCPHDRDATA_SIZE = TOT_SIZE - IPHDR_SIZE;
    unsigned short len_tcp = TCPHDRDATA_SIZE;

    chk_p.pseudohdr.saddr = pkt->ip.saddr;
    chk_p.pseudohdr.daddr = pkt->ip.daddr;
    chk_p.pseudohdr.proto = IPPROTO_TCP;
    chk_p.pseudohdr.tcp_len = htons(len_tcp);

    memcpy(&chk_p.tcp, &pkt->tcp, sizeof(struct tcphdr));
    memcpy(&chk_p.payload, &pkt->payload, len_tcp - sizeof(struct tcphdr));

    return in_cksum(&chk_p, sizeof(struct pseudotcphdr) + len_tcp);
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

            if (tsval) *tsval = ntohl(ptr[0]);
            if (tsecho) *tsecho = ntohl(ptr[1]);

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

                    if (tsval) *tsval = ntohl(ts[0]);
                    if (tsecho) *tsecho = ntohl(ts[1]);

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

            if (tsval) ptr[0] = htonl(*tsval);
            if (tsecho) ptr[1] = htonl(*tsecho);

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

                    if (tsval) ts[0] = htonl(*tsval);
                    if (tsecho) ts[1] = htonl(*tsecho);

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

/*
 * NAT Ethernet and IP header, fix checksums
 * Only for non-forwarded connections!
 */
static inline void nat(struct pkt_struct* pkt) {

    memcpy(&pkt->packet.eth->ether_shost, &pkt->out->mac.addr_eth, ETH_ALEN);

    switch (pkt->origin) {
        case INT:
        case LIH:
        case HIH:

            //SNAT

            memcpy(&pkt->packet.eth->ether_dhost, &pkt->nat.dst_mac->addr_eth,
                    ETH_ALEN);
            memcpy(&pkt->packet.ip->saddr, &pkt->nat.src_ip->addr_ip,
                    sizeof(ip_addr_t));

            if(ntohs(pkt->packet.eth->ether_type) == ETHERTYPE_VLAN) {
                // Uplink VLANs should be configured with the 8021q kernel module
                // so we are stripping any VLAN header downlink had
                printdbg("%s Stripping VLAN header from downlink packet\n", H(1));

                memmove(pkt->packet.FRAME + VLAN_HLEN, pkt->packet.FRAME, ETHER_HDR_LEN);
                pkt->packet.eth = (struct ether_header *)(pkt->packet.FRAME + VLAN_HLEN);
                pkt->packet.eth->ether_type = htons(ETHERTYPE_IP);
                pkt->size -= VLAN_HLEN;
            }

            break;
        case EXT:
        default:

            //DNAT

            memcpy(&pkt->packet.eth->ether_dhost, &pkt->nat.dst_mac->addr_eth,
                    ETH_ALEN);
            memcpy(&pkt->packet.ip->daddr, &pkt->nat.dst_ip->addr_ip,
                    sizeof(ip_addr_t));

            // Downlink is a VLAN
            if (pkt->nat.dst_vlan && pkt->nat.dst_vlan->v.vid) {

                printdbg("%s Downlink is a VLAN, NATing accordingly\n", H(1));

                // Regular ethernet headers are not at the start of FRAME
                // to save space for this scenario, so we just move it there
                memmove(pkt->packet.FRAME, pkt->packet.eth, ETHER_HDR_LEN);
                pkt->packet.vlan = (struct vlan_ethhdr *) pkt->packet.FRAME;
                pkt->packet.vlan->h_vlan_proto = htons(ETHERTYPE_VLAN);
                pkt->packet.vlan->h_vlan_encapsulated_proto =
                        htons(ETHERTYPE_IP);
                pkt->packet.vlan->h_vlan_TCI = *(pkt->nat.dst_vlan);
                pkt->size += VLAN_HLEN;

            } else if (ntohs(pkt->packet.eth->ether_type) == ETHERTYPE_VLAN) {

                printdbg(
                        "%s Downlink isn't a VLAN, stripping VLAN header\n", H(1));

                // Downlink isn't a VLAN but packet has a VLAN header, strip it
                memmove(pkt->packet.FRAME + VLAN_HLEN, pkt->packet.FRAME,
                        ETHER_HDR_LEN);
                pkt->packet.eth = (struct ether_header *) (pkt->packet.FRAME
                        + VLAN_HLEN);
                pkt->packet.eth->ether_type = htons(ETHERTYPE_IP);
                pkt->size -= VLAN_HLEN;
            }

            break;
    }

    if (pkt->packet.ip->protocol == IPPROTO_TCP) {
        set_tcp_checksum(pkt->packet.tcppacket);
    } else {
        set_udp_checksum(pkt->packet.udppacket);
    }

    set_ip_checksum(pkt->packet.ip);
}

/*! proxy
 *
 \brief proxy the packet to it's destination
 \param[in] pkt, the packet metadata structure to forward

 \return OK if the packet has been succesfully sent
 */
status_t proxy_ext(struct pkt_struct* pkt) {

    //DNAT
    switch (pkt->conn->initiator) {
        case LIH:
        case EXT:
            pkt->out = pkt->conn->target->front_handler->iface;
            pkt->nat.dst_mac = pkt->conn->target->front_handler->mac;
            pkt->nat.dst_ip = pkt->conn->target->front_handler->ip;
            pkt->nat.dst_vlan = &pkt->conn->target->front_handler->vlan;
            break;
        case HIH:
            pkt->out = pkt->conn->hih.iface;
            pkt->nat.dst_mac = pkt->conn->hih.mac;
            pkt->nat.dst_ip = pkt->conn->hih.ip;
            pkt->nat.dst_vlan = pkt->conn->hih.vlan;
            break;
        default:
            return NOK;
    }

    nat(pkt);

    printdbg("%s Sending PROXY packet on %s\n", H(6), pkt->out->tag);

    if (pkt->out
            && pcap_inject(pkt->out->pcap, pkt->packet.eth, pkt->size) != -1) {
        return OK;
    }

    return NOK;
}

status_t proxy_int(struct pkt_struct* pkt) {

    pkt->out = pkt->conn->target->default_route;

    //SNAT
    pkt->nat.src_ip = &pkt->conn->first_pkt_dst_ip;
    pkt->nat.dst_mac = &pkt->conn->first_pkt_src_mac;
    pkt->nat.dst_ip = &pkt->conn->first_pkt_src_ip;

    nat(pkt);

    printdbg("%s Sending PROXY packet on %s\n", H(6), pkt->out->tag);

    if (pkt->out
            && pcap_inject(pkt->out->pcap, pkt->packet.eth, pkt->size) != -1) {
        return OK;
    }

    return NOK;
}
/*
 * Forward packets coming from EXT to HIH
 */
status_t forward_ext(struct pkt_struct* pkt) {

    pkt->out=pkt->conn->hih.iface;

    memcpy(&pkt->packet.eth->ether_shost, &pkt->out->mac.addr_eth,
                ETH_ALEN);
    memcpy(&pkt->packet.eth->ether_dhost, &pkt->conn->hih.mac->addr_eth,
            ETH_ALEN);
    memcpy(&pkt->packet.ip->daddr, &pkt->conn->hih.ip->addr_ip,
            sizeof(ip_addr_t));

    if (pkt->conn->hih.vlan) {
        if(pkt->packet.eth->ether_type != htons(ETHERTYPE_VLAN)) {
            // Regular ethernet headers are not at the start of FRAME
            // to save space for this scenario, so we just move it there
            memmove(pkt->packet.FRAME, pkt->packet.eth, ETHER_HDR_LEN);
            pkt->size+= VLAN_HLEN;
        }

        pkt->packet.vlan = (struct vlan_ethhdr *) pkt->packet.FRAME;
        pkt->packet.vlan->h_vlan_proto = htons(ETHERTYPE_VLAN);
        pkt->packet.vlan->h_vlan_encapsulated_proto = htons(ETHERTYPE_IP);
        pkt->packet.vlan->h_vlan_TCI = *(pkt->conn->hih.vlan);
    }

    printdbg(
            "%s forwarding packet to HIH %lu\n", H(pkt->conn->id), pkt->conn->hih.hihID);

    /*!If TCP, we update the destination port, the acknowledgement number if any, and the checksum*/
    switch (pkt->packet.ip->protocol) {
        case IPPROTO_TCP:

            pkt->packet.tcp->dest = pkt->conn->hih.port;
            if (pkt->packet.tcp->ack == 1) {
                pkt->packet.tcp->ack_seq = htonl(
                        ntohl(pkt->packet.tcp->ack_seq)
                        + ~(pkt->conn->hih.delta) + 1);
            }

            set_tcp_checksum(pkt->packet.tcppacket);
            break;

            /*!If UDP, we update the destination port and the checksum*/
        case IPPROTO_UDP:

            pkt->packet.udp->dest = pkt->conn->hih.port;
            set_udp_checksum(pkt->packet.udppacket);
            break;
    }

    set_ip_checksum(pkt->packet.ip);

    if (pkt->out
            && pcap_inject(pkt->out->pcap, pkt->packet.eth, pkt->size) != -1) {
        return OK;
    }

    return NOK;

}

/*
 * Forward packets coming from a HIH
 */
status_t forward_hih(struct pkt_struct* pkt) {

    pkt->out = pkt->conn->target->default_route;

    memcpy(&pkt->packet.eth->ether_shost, &pkt->conn->first_pkt_dst_mac.addr_eth,
            ETH_ALEN);
    memcpy(&pkt->packet.eth->ether_dhost, &pkt->conn->first_pkt_src_mac.addr_eth,
                ETH_ALEN);
    memcpy(&pkt->packet.ip->saddr, &pkt->conn->first_pkt_dst_ip.addr_ip,
            sizeof(ip_addr_t));

    if(ntohs(pkt->packet.eth->ether_type) == ETHERTYPE_VLAN) {
        // Uplink VLANs should be configured with the 8021q kernel module
        // so we are stripping any VLAN header downlink had
        printdbg("%s Stripping VLAN header from downlink packet\n", H(1));

        memmove(pkt->packet.FRAME + VLAN_HLEN, pkt->packet.FRAME, ETHER_HDR_LEN);
        pkt->packet.eth = (struct ether_header *)(pkt->packet.FRAME + VLAN_HLEN);
        pkt->packet.eth->ether_type = htons(ETHERTYPE_IP);
        pkt->size -= VLAN_HLEN;
    }

    printdbg("%s forwarding packet to EXT\n", H(pkt->conn->id));

    /*!If TCP, we update the source port, the sequence number, and the checksum*/
    switch (pkt->packet.ip->protocol) {
        case IPPROTO_TCP:
            pkt->packet.tcp->source = pkt->conn->hih.port;
            pkt->packet.tcp->seq = htonl(
                    ntohl(pkt->packet.tcp->seq) + pkt->conn->hih.delta);

            fix_tcp_timestamps(pkt->packet.tcp, pkt->conn);
            set_tcp_checksum(pkt->packet.tcppacket);

            break;
            /*!If UDP, we update the source port and the checksum*/
        case IPPROTO_UDP:
            pkt->packet.udp->source =
                    pkt->conn->hih.port;

            set_udp_checksum(pkt->packet.udppacket);

            break;
    }

    set_ip_checksum(pkt->packet.ip);

    if (pkt->out
            && pcap_inject(pkt->out->pcap, pkt->packet.eth, pkt->size) != -1) {
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

        uint32_t size;
        unsigned char frame[VLAN_ETH_HLEN + sizeof(struct tcp_packet)];
        struct ether_header *eth = (struct ether_header *) frame;
        struct tcp_packet *rst;

        if(pkt->original_headers.vlan) {
            size = VLAN_ETH_HLEN + sizeof(struct tcp_packet);
            struct vlan_ethhdr *vlan = (struct vlan_ethhdr *) frame;
            *vlan = *(pkt->original_headers.vlan);
            rst = (struct tcp_packet *) (frame + VLAN_ETH_HLEN);
        } else {
            size = ETHER_HDR_LEN + sizeof(struct tcp_packet);
            *eth = *(pkt->original_headers.eth);
            rst = (struct tcp_packet *) (frame + ETHER_HDR_LEN);
        }

        /*! fill up the IP header */
        rst->ip.version = 4;
        rst->ip.ihl = sizeof(struct iphdr) >> 2;
        rst->ip.tot_len = ntohs(sizeof(struct iphdr) + sizeof(struct tcphdr));
        rst->ip.frag_off = ntohs(0x4000);
        rst->ip.ttl = 0x40;
        rst->ip.protocol = IPPROTO_TCP;
        rst->ip.saddr = pkt->original_headers.ip->daddr;
        rst->ip.daddr = pkt->original_headers.ip->saddr;

        /*! fill up the TCP header */
        rst->tcp.source = pkt->original_headers.tcp->dest;
        rst->tcp.dest = pkt->original_headers.tcp->source;
        if (pkt->original_headers.tcp->ack == 1) rst->tcp.seq =
                (pkt->original_headers.tcp->ack_seq);
        rst->tcp.ack_seq =
                htonl(
                        ntohl(pkt->original_headers.tcp->seq) + pkt->original_headers.tcp->syn +pkt->original_headers.tcp->fin
                        + ntohs(pkt->original_headers.ip->tot_len) - (pkt->original_headers.ip->ihl << 2)
                        - (pkt->original_headers.tcp->doff << 2));
        rst->tcp.doff = 0x5;
        rst->tcp.rst = 0x1;
        rst->tcp.ack = 0x1;

        set_tcp_checksum(rst);
        set_ip_checksum(&rst->ip);

        pcap_inject(iface->pcap, frame, size);
    }
}

/*! reset_lih
 *
 \brief reset the LIH when redirected to HIH
 \param[in] conn: the connnection that the LIH reset
 */

void reset_lih(struct conn_struct* conn) {

    //! reset only tcp connections
    if (conn->protocol != IPPROTO_TCP) return;

    struct packet *p = NULL;
    struct pkt_struct* tmp;
    printdbg("%s Reseting LIH\n", H(conn->id));

    GSList * current = (GSList *) conn->BUFFER;
    do {
        tmp = (struct pkt_struct*) g_slist_nth_data(current, 0);
        if (tmp->origin == LIH) {
            p = &tmp->packet;
        }
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

    if (pkt->origin != HIH) goto done;

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

            if (current->origin == EXT) forward_ext(current);

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
                "%s Unexpected protocol: %s. Expected %s\n", H(conn->id), lookup_proto(pkt->packet.ip->protocol), lookup_proto(conn->expected_data.ip_proto));

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

    if (flag == OK) {
        printdbg("%s Expected data OK\n", H(conn->id));
    }

    test_done: return flag;
}
