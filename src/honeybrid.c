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

/*!	\mainpage Hybrid Honeypot Gateway
 *
 * 	\section Introduction
 *
 * 	This project is a honeypot architecture able to combine low and high interaction honeypots in the same framework.
 * 	The objective is to have a scalable solutions and to collect detailed attack processes.
 * 	The core of the project is a software gateway based on Iptables and built upon two engines: a Redirection Engine and a Decision Engine.
 * 	The concept of the architecture is to use a front end of low interaction honeypot to reply to all incoming traffic.
 * 	Then the goal of the Decision Engine is to filter interesting attacks from the noise of incoming traffic received.
 * 	Filtered attacks are forwarded to the Redirection Engine which is able to actively redirect the destination of the connection, so that it can be further investigated using a high interaction back-end.
 *
 */

/*!	\file honeybrid.c
 \brief Main File

 This is the main program file for Honeybrid. It creates a hook using LibNetfilter Queue
 and, for each connection, maintain a stateful table.
 It forwards a packet to a determined destination and submits this packet to the decision engine.
 When the decision engine decides to redirect a connection, this redirection engine replays the recorded
 connection to its new destination and maintains it until its end.

 Packets needs to be redirected to the QUEUE destination using netfilter, this can be done using:
 # iptables -A INPUT -j QUEUE && iptables -A FORWARD -j QUEUE && iptables -A OUTPUT -j QUEUE

 Other filters can also be set up using the regulars iptables capabilities,
 it is also recommended to limit the redirections to TCP and UDP packets
 (just add the option -p to the iptables commands)

 \Author J. Vehent, 2007
 \Author Thomas Coquelin, 2008
 \Author Robin Berthier, 2007-2009
 \Author Tamas K Lengyel, 2012-2013
 */

/* \todo to include in programmer documentation:
 //What we should use to log messages:
 //For debugging:
 printdbg("%smessage\n", H(30));

 //For processing information:
 syslog(LOG_INFO,"message");

 //For critical warning
 warn("open");
 warnx("%s message", __func__);

 //For fatal error
 err("fopen");
 errx(1,"%s message", __func__);
 */

#include "honeybrid.h"

#include <limits.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <execinfo.h>

#include "constants.h"
#include "structs.h"
#include "globals.h"
#include "convenience.h"
#include "netcode.h"
#include "log.h"
#include "decision_engine.h"
#include "modules.h"
#include "connections.h"

// Get the Queue ID the packet should be assigned to
// based on the last byte of the external IP
#define IP2QUEUEID(iface, ip) \
    (iface->target) ? \
            (((ip->saddr & 0xFF000000) >> 24) % decision_threads) \
            : \
            (((ip->daddr & 0xFF000000) >> 24) % decision_threads)

void pcap_looper(struct interface *iface);

GThread **pcap_loopers;

/*! usage function
 \brief print command line informations */
void usage(char **argv) {
    g_printerr(
            "Usage: %s <commands>\n\n"
                    "Where commands include:\n"
                    "  -c <config_file>: start with config file\n"
                    "            For example: honeybrid -c /etc/honeybrid.conf\n"
                    "  -x <pid>: halt a running engine using its PID\n"
                    "            For example: honeybrid -x `cat /var/run/honeybrid.pid`\n"
                    "  -q <queuenum>: select a specific queue number for NF_QUEUE to listen to\n"
                    "  -d: daemonize Honeybrid (send it to the background)\n"
                    //"  -s: show status information\n"
                    "  -h: print this help\n\n", argv[0]);
    exit(1);
}

/*! term_signal_handler
 *
 \brief called when the program receive a signal that should close the program, free memory and delete lock file
 *
 \param[in] signal_nb: number of the signal
 \param[in] siginfo: informations regarding to the signal
 \param[in] context: NULL */
static void term_signal_handler(int signal_nb, siginfo_t * siginfo,
        __attribute__((unused)) void *unused) {
    printdbg("%s: Signal %d received, halting engine\n", __func__, signal_nb);
    printdbg("* Signal number:\t%d\n", siginfo->si_signo);
    printdbg("* Signal code:  \t%d\n", siginfo->si_code);
    printdbg(
            "* Signal error: \t%d '%s'\n", siginfo->si_errno, strerror(siginfo->si_errno));
    printdbg("* Sending pid:  \t%d\n", siginfo->si_pid);
    printdbg("* Sending uid:  \t%d\n", siginfo->si_uid);
    printdbg("* Fault address:\t%p\n", siginfo->si_addr);
    printdbg("* Exit value:   \t%d\n", siginfo->si_status);

    /*! this will cause the queue loop to stop */
    running = NOK;

    GHashTableIter i;
    char *key = NULL;
    struct interface *iface = NULL;
    ghashtable_foreach(links, i, key, iface)
    {
        pcap_breakloop(iface->pcap);
    }
}

/*! init_signal
 \brief installs signal handlers
 \return 0 if exit with success, anything else if not */
void init_signal() {
    /*! Install terminating signal handler: */
    struct sigaction sa_term;
    memset(&sa_term, 0, sizeof sa_term);

    sa_term.sa_sigaction = (void *) term_signal_handler;
    sa_term.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigfillset(&sa_term.sa_mask);

    /*! SIGHUP*/
    if (sigaction(SIGHUP, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGHUP", __func__);

    /*! SIGINT*/
    if (sigaction(SIGINT, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGINT", __func__);

    /*! SIGQUIT*/
    if (sigaction(SIGQUIT, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGQUIT", __func__);

    /*! SIGILL*/
    if (sigaction(SIGILL, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGILL", __func__);

    /*! SIGSEGV*/
    if (sigaction(SIGSEGV, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGSEGV", __func__);

    /*! SIGTERM*/
    if (sigaction(SIGTERM, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGTERM", __func__);

    /*! SIGBUS*/
    if (sigaction(SIGBUS, &sa_term, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGBUS", __func__);

    /*! ignore signals: */
    struct sigaction sa_ignore;
    memset(&sa_ignore, 0, sizeof sa_ignore);
    sa_ignore.sa_handler = SIG_IGN;
    sigfillset(&sa_ignore.sa_mask);

    /*! SIGABRT*/
    if (sigaction(SIGABRT, &sa_ignore, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGABRT", __func__);

    /*! SIGALRM*/
    if (sigaction(SIGALRM, &sa_ignore, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGALRM", __func__);

    /*! SIGUSR2*/
    if (sigaction(SIGUSR2, &sa_ignore, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGUSR2", __func__);

    /*! SIGPOLL*/
    if (sigaction(SIGPOLL, &sa_ignore, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGPOLL", __func__);

    /*! rotate logs: */
    struct sigaction sa_rotate_log;
    memset(&sa_rotate_log, 0, sizeof(sa_rotate_log));

    sa_rotate_log.sa_sigaction = (void *) rotate_connection_log;
    //sa_rotate_log.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sa_rotate_log.sa_flags = SA_RESTART;
    sigfillset(&sa_rotate_log.sa_mask);

    /*! SIGUSR1*/
    if (sigaction(SIGUSR1, &sa_rotate_log, NULL) != 0) errx(1,
            "%s: Failed to install sighandler for SIGUSR1", __func__);
}

/*! init_syslog
 \brief initialize syslog logging */
static void init_syslog(int argc, char *argv[]) {
    int options, i;
    char buf[MAXPATHLEN];

#ifdef LOG_PERROR
    options = LOG_PERROR | LOG_PID | LOG_CONS;
#else
    options = LOG_PID|LOG_CONS;
#endif
    openlog("honeybrid", options, LOG_DAEMON);

    /* Create a string containing all the command line
     * arguments and pass it to syslog:
     */

    buf[0] = '\0';
    for (i = 1; i < argc; i++) {
        if (i > 1 && g_strlcat(buf, " ", sizeof(buf)) >= sizeof(buf)) break;
        if (g_strlcat(buf, argv[i], sizeof(buf)) >= sizeof(buf)) break;
    }

    syslog(LOG_NOTICE, "started with %s", buf);
}

/*! parse_config
 \brief Configuration parsing function, read the configuration from a specific file 
 and parse it into a hash table or other tree data structures using Bison/Flex
 */
void init_parser(char *filename) {

    g_printerr("--------------------------\nReading configuration\n");

    FILE *fp = fopen(filename, "r");
    if (!fp) err(1, "fopen(%s)", filename);

    //extern int yydebug;
    //yydebug = 1;
    yyin = fp;
    yyparse();

    fclose(fp);

    g_printerr("--------------------------\n");
}

void init_variables() {
    /*! create the hash table to store the config */
    if (NULL
            == (config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                    g_free))) errx(1,
            "%s: Fatal error while creating config hash table.\n", __func__);

    /*! create the array of pointer to store the target information */
    if (NULL
            == (targets = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                    (GDestroyNotify) free_target))) errx(1,
            "%s: Fatal error while creating target hash table.\n", __func__);

    /*! create the hash table to store module information */
    if (NULL
            == (module = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                    (GDestroyNotify) g_hash_table_destroy))) errx(1,
            "%s: Fatal error while creating module hash table.\n", __func__);

    /*! create the hash table for the log engine */
    if (NULL
            == (links = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                    (GDestroyNotify) free_interface))) errx(1,
            "%s: Fatal error while creating links hash table.\n", __func__);

    /*! create the tree that locks active hih connections to the same target */
    if (NULL
            == (active_hihs = g_tree_new_full((GCompareDataFunc) intcmp, NULL,
                    g_free, NULL))) errx(1,
            "%s: Fatal error while creating links hash table.\n", __func__);

    /* create the main B-Tree to store meta informations of active connections */
    if (NULL == (conn_tree = g_tree_new((GCompareFunc) addr_cmp))) {
        errx(1, "%s: Fatal error while creating conn_tree.\n", __func__);
    }

    /*! create the hash table for the log engine */
    if (NULL == (module_to_save = g_hash_table_new(g_str_hash, g_str_equal))) errx(
            1, "%s: Fatal error while creating module_to_save hash table.\n",
            __func__);

    /*! create the redirection table */
    /*if (NULL
     == (high_redirection_table = g_hash_table_new_full(g_str_hash,
     g_str_equal, g_free, g_free))) errx(1,
     "%s: Fatal error while creating high_redirection_table hash table.\n",
     __func__);*/

    /* set debug file */
    fdebug = -1;

    /*! init the connection id counter */
    c_id = 0;

    /*! Enable threads */
    threading = OK;

    /*! Enable data processing */
    running = OK;
}


/*! init_pcap
 \brief Initialize pcap capture on each interface and start their respective threads */
void init_pcap() {

    GHashTableIter i;
    char *key = NULL;
    struct interface *iface = NULL;

    ghashtable_foreach(links, i, key, iface)
    {

        set_iface_info(iface);

        char pcapErr[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(iface->name, &iface->ip_network, &iface->netmask,
                pcapErr) < 0) {
            errx(1,
                    "%s Couldn't get network interface information on %s: %s!\n",
                    __func__, iface->name, pcapErr);
        }

        iface->pcap = pcap_open_live(iface->name, BUFSIZE, 0, -1,
                pcapErr);

        if (iface->pcap == NULL) {
            errx(1, "%s Failed to open pcap interface on %s: %s!\n", __func__,
                    iface->name, pcapErr);
        }

        if (iface->filter) {

            printdbg(
                    "%s Compiling filter '%s' for interface %s (%s)\n", H(5), iface->filter, iface->tag, iface->name);

            if (pcap_compile(iface->pcap, &iface->pcap_filter, iface->filter, 1,
                    iface->netmask) == -1) {
                errx(1, "Counldn't parse filter %s: %s\n", iface->filter,
                        pcap_geterr(iface->pcap));
                return;
            }

            if (pcap_setfilter(iface->pcap, &iface->pcap_filter) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n",
                        iface->filter, pcap_geterr(iface->pcap));
                return;
            }
        }

        if ((iface->pcap_looper = g_thread_new("pcap_looper",
                (void *) pcap_looper, iface)) == NULL) {
            errx(1, "%s Cannot create pcap_looper thread", H(6));
        }
    }
}


/*! wait_pcap
 \brief Wait till all pcap looper threads exit */
void wait_pcap() {
    GHashTableIter i;
    char *key = NULL;
    struct interface *iface = NULL;

    ghashtable_foreach(links, i, key, iface)
    {
        g_thread_join(iface->pcap_looper);
        pcap_close(iface->pcap);
    }
}

/*! close_thread
 \brief Function that waits for thread to close themselves */
int close_thread() {

    /* First, let's make sure all packets already queued get processed */
    uint32_t i;
    struct raw_pcap raw = { .last = TRUE };
    for (i = 0; i < decision_threads; i++) {
        g_async_queue_push(de_queues[i], &raw);
        printdbg("%s: Waiting for de_thread %i to terminate\n", H(0), i);
        g_thread_join(de_threads[i]);
        g_async_queue_unref(de_queues[i]);
    }

    /* Shut down other threads */
    threading = NOK;
    g_cond_broadcast(&threading_cond);

    g_thread_join(mod_backup);
    g_thread_join(thread_clean);

    return 0;
}

/*! close_hash function
 \brief Destroy the different hashes used by honeybrid */
int close_hash() {
    /*! Destroy hash tables
     */

    /*if (high_redirection_table != NULL) {
     printdbg("%s: Destroying table high_redirection_table\n", H(0));
     g_rw_lock_writer_lock(&hihredirlock);
     g_hash_table_destroy(high_redirection_table);
     high_redirection_table = NULL;
     }*/

    if (config != NULL) {
        printdbg("%s: Destroying table config\n", H(0));
        g_hash_table_destroy(config);
        config = NULL;
    }

    if (module != NULL) {
        printdbg("%s: Destroying table module\n", H(0));
        g_hash_table_destroy(module);
    }

    if (links != NULL) {
        printdbg("%s: Destroying table links\n", H(0));
        g_hash_table_destroy(links);
        links = NULL;
    }

    if (module_to_save != NULL) {
        printdbg("%s: Destroying table module_to_save\n", H(0));
        g_hash_table_destroy(module_to_save);
        module_to_save = NULL;
    }

    if (targets != NULL) {
        printdbg("%s: Destroying table targets\n", H(0));
        g_hash_table_destroy(targets);
        targets = NULL;
    }

    return 0;
}

/*! close_conn_tree function
 \brief Function to free memory taken by conn_tree */
int close_conn_tree() {

    printdbg("%s: Destroying connection tree\n", H(0));

    /*! clean the memory
     * traverse the B-Tree to remove the singly linked lists and then destroy the B-Tree
     */
    int delay = 0;
    entrytoclean = g_ptr_array_new_with_free_func(g_free);

    g_mutex_lock(&connlock);

    /*! call the clean function for each value, delete the value if TRUE is returned */
    g_tree_foreach(conn_tree, (GTraverseFunc) expire_conn, GINT_TO_POINTER(delay));

    /*! remove each key listed from the btree */
    g_ptr_array_foreach(entrytoclean, (GFunc) remove_conn, NULL);

    /*! free the array */
    g_ptr_array_free(entrytoclean, TRUE);
    entrytoclean = NULL;

    g_tree_destroy(conn_tree);
    conn_tree = NULL;

    return 0;
}

/*! close_all
 \brief destroy structures and free memory when the program has to quit */
void close_all(void) {
    /*! wait for thread to close */
    if (close_thread() < 0) g_printerr(
            "%s: Error when waiting for threads to close\n", H(0));

    /*! delete conn_tree */
    if (close_conn_tree() < 0) g_printerr("%s: Error when closing conn_tree\n",
            H(0));

    /*! delete lock file */
    if (unlink(pidfile) < 0) g_printerr("%s: Error when removing lock file\n",
            H(0));

    /*! close log file */
    if (OUTPUT_LOGFILES == ICONFIG_REQUIRED("output")) {
        close_connection_log();
    }

    /*! close debug log file */
    if (fdebug != -1) {
        close_debug_log();
    }

    /*! delete hashes */
    if (close_hash() < 0) {
        printdbg("%s: Error when closing hashes\n", H(0));
    }
}

void pcap_cb(u_char *input, const struct pcap_pkthdr *header,
        const u_char *packet) {

    if (header->len != header->caplen) {
        printdbg("%s Truncated packet. Captured %u out of %u bytes. Skipped.\n", H(4), header->caplen, header->len);
        return;
    }

    struct interface *iface = (struct interface *) input;
    struct iphdr *ip = NULL;
    struct vlan_ethhdr *veth = NULL;
    uint16_t ethertype = ntohs(((struct ether_header *)packet)->ether_type);

    switch (ethertype) {
        case ETHERTYPE_IP:
            ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
            break;
        case ETHERTYPE_VLAN:

            // Uplink VLANs have to be configured with 8021q kernel module
            if(iface->target) {
                printdbg(
                        "%s Packet is from an uplink VLAN. Skipped.\n", H(4));
                return;
            }

            veth = (struct vlan_ethhdr *) packet;

            switch (ntohs(veth->h_vlan_encapsulated_proto)) {
                case ETHERTYPE_IP:
                    ip = (struct iphdr *) (packet + VLAN_ETH_HLEN);
                    break;
                case ETHERTYPE_ARP:
                    send_arp_reply(ethertype, (struct interface *)input, packet);
                    return;
                    break;
                default:
                    printdbg(
                            "%s Invalid encapsulated VLAN ethernet type: %u. Skipped.\n", H(4), ntohs(veth->h_vlan_encapsulated_proto));
                    return;
                    break;

            }

            break;
        default:
            printdbg(
                    "%s Invalid ethernet type: %u. Skipped.\n", H(4), ethertype);
            return;
            break;
    }

    struct raw_pcap *raw = malloc(sizeof(struct raw_pcap));
    raw->header = g_memdup(header, sizeof(struct pcap_pkthdr));
    raw->packet = g_memdup(packet, header->caplen);
    raw->iface = iface;
    raw->last = FALSE;

    uint32_t queue_id = IP2QUEUEID(iface, ip);

    printdbg(
            "%s** RAW packet of size %u pushed to queue %u **\n", H(0), header->len, queue_id);

    g_async_queue_push(de_queues[queue_id], raw);

}

void pcap_looper(struct interface *iface) {
    if (iface) {
        pcap_loop(iface->pcap, -1, pcap_cb, (u_char *) iface);
    } else {
        errx(1, "%s can't start. Iface is NULL\n", __func__);
    }
}

/*! process_packet
 *
 \brief Function called for each received packet. It's thread safe. */
status_t process_packet(struct interface *iface,
        const struct pcap_pkthdr *header, const u_char *packet,
        struct pkt_struct **pkt) {

    if (header->len < MIN_PACKET_SIZE) {
        printdbg("%s Invalid packet size: %u. Skipped.\n", H(4), header->len);
        return NOK;
    }

    struct ether_header *eth = (struct ether_header *) packet;
    uint16_t ethertype = ntohs(eth->ether_type);
    struct iphdr *ip = NULL;

    /*! Catch TCP and UDP packets */
    switch (ntohs(((struct ether_header *) packet)->ether_type)) {
        case ETHERTYPE_IP:
            ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
            break;
        case ETHERTYPE_VLAN:
            if (ntohs(((struct vlan_ethhdr *) packet)->h_vlan_encapsulated_proto) == ETHERTYPE_IP) {
                ip = (struct iphdr *) (packet + VLAN_ETH_HLEN);
            } else {
                printdbg(
                        "%s Invalid encapsulated VLAN ethernet type. Skipped.\n", H(4));
                return NOK;
            }
            break;
        default:
            printdbg( "%s Invalid ethernet type. Skipped.\n", H(4));
            return NOK;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        printdbg("%s Invalid IP protocol: %u. Skipped\n", H(4), ip->protocol);
        return NOK;
    }

    if (ip->ihl < 0x5 || ip->ihl > 0x08) {
        printdbg("%s Invalid IP header length: %u. Skipped.\n", H(4), ip->ihl);
        return NOK;
    }

    if (ntohs(ip->tot_len) > header->len) {
        printdbg(
                "%s Truncated packet: %u/%u. Skipped.\n", H(4), header->len, ntohs(ip->tot_len));
        return NOK;
    }

    *pkt = NULL;

    /*! Initialize the packet structure (into pkt) and find the origin of the packet */
    if (init_pkt(iface, ethertype, header, packet, pkt) == NOK) {
        printdbg("%s Packet structure couldn't be initialized\n", H(0));

        *pkt = NULL;
        return NOK;

    }

    return OK;
}

void de_thread(gpointer data) {

    uint32_t thread_id = GPOINTER_TO_UINT(data);
    struct raw_pcap *raw = NULL;

    printdbg("%s: Decision engine thread %i started\n", H(0), thread_id);

    while ((raw = (struct raw_pcap *) g_async_queue_pop(de_queues[thread_id]))) {

        printdbg("%s Got a RAW packet from queue %u\n", H(0), thread_id);

        struct pkt_struct *pkt = NULL;
        struct conn_struct *conn = NULL;

        // Exit the thread
        if (raw->last) {
            printdbg("%s Shutting down thread %u\n", H(1), thread_id);
            return;
        }

        if (process_packet(raw->iface, raw->header, raw->packet, &pkt) == NOK) {
            free_raw_pcap(raw);
            goto done;
        }
        free_raw_pcap(raw);

        /*! Initialize the connection structure (into conn) and get the state of the connection */
        if (init_conn(pkt, &conn) == NOK) {
            conn = NULL;
            printdbg(
                    "%s Connection structure couldn't be initialized, packet dropped\n", H(0));
            free_pkt(pkt);
            goto done;
        }

        printdbg(
                "%s Origin: %s %s, %u bytes with %u bytes of data\n", H(conn->id), lookup_origin(pkt->origin), lookup_state(conn->state), pkt->size, pkt->data);

        /*! Check that there was no problem getting the current connection structure
         *  and make sure the STATE is valid */
        if ((conn->state < INIT || conn->state >= __MAX_CONN_STATUS)
                && pkt->origin == EXT) {

            printdbg("%s Packet not from a valid connection\n", H(conn->id));
            if (pkt->origin == EXT && pkt->packet.ip->protocol == IPPROTO_TCP
                    && reset_ext == 1) {
                reply_reset(pkt, pkt->conn->target->default_route);
            }

            free_pkt(pkt);
            goto done;
        }

        if (conn->state == DROP) {

            printdbg("%s This connection is marked as DROPPED\n", H(conn->id));
            if (pkt->origin == EXT && pkt->packet.ip->protocol == IPPROTO_TCP
                    && reset_ext == 1) {
                reply_reset(pkt, pkt->conn->target->default_route);
            }

            free_pkt(pkt);
            goto done;
        }

        switch (pkt->origin) {
            /*! Packet is from the low interaction honeypot */
            case LIH:
                switch (conn->state) {
                    case INIT:
                        if (pkt->packet.ip->protocol == IPPROTO_TCP
                                && pkt->packet.tcp->syn != 0) {
                            conn->hih.lih_syn_seq = ntohl(pkt->packet.tcp->seq);
                        }

                        proxy_int(pkt);

                        // Only store packets if there are backends
                        if (conn->target->back_handler_count > 0) {
                            store_pkt(conn, pkt);
                        } else {
                            free_pkt(pkt);
                        }

                        break;
                    case DECISION:
                        if (pkt->packet.ip->protocol == IPPROTO_TCP
                                && pkt->packet.tcp->syn != 0) {
                            conn->hih.lih_syn_seq = ntohl(pkt->packet.tcp->seq);
                        }

                        proxy_int(pkt);

                        // Only store packets if there are backends
                        if (conn->target->back_handler_count > 0) {
                            store_pkt(conn, pkt);
                        } else {
                            free_pkt(pkt);
                        }

                        break;
                    case PROXY:
                        printdbg(
                                "%s Packet from LIH proxied directly to its destination\n", H(conn->id));
                        proxy_int(pkt);
                        free_pkt(pkt);
                        break;
                    case CONTROL:
                        if (pkt->packet.ip->protocol == IPPROTO_TCP
                                && pkt->packet.tcp->syn != 0) {
                            conn->hih.lih_syn_seq = ntohl(pkt->packet.tcp->seq);
                        }

                        if (DE_process_packet(pkt) == OK) {
                            proxy_int(pkt);
                        }

                        // Only store packets if there are backends
                        if (conn->target->back_handler_count > 0) {
                            store_pkt(conn, pkt);
                        } else {
                            free_pkt(pkt);
                        }
                        break;
                    default:
                        printdbg(
                                "%s Packet from LIH at wrong state => reset\n", H(conn->id));
                        if (pkt->packet.ip->protocol == IPPROTO_TCP) reply_reset(
                                pkt, pkt->conn->target->front_handler->iface);
                        free_pkt(pkt);
                        break;
                }
                break;

            case HIH:
                /*! Packet is from the high interaction honeypot */
                switch (conn->state) {
                    case REPLAY:
                        /*! push the packet to the synchronization list in conn_struct */
                        if (pkt->packet.ip->protocol == IPPROTO_TCP
                                && pkt->packet.tcp->syn == 1) {
                            conn->hih.delta = ~ntohl(pkt->packet.tcp->seq) + 1
                                    + conn->hih.lih_syn_seq;
                        }
                        replay(conn, pkt);
                        free_pkt(pkt);
                        break;
                    case FORWARD:
                        forward_hih(pkt);
                        free_pkt(pkt);
                        break;
                        /*! This one should never occur because PROXY are only between EXT and LIH... but we never know! */
                    case PROXY:
                        printdbg(
                                "%s Packet from HIH proxied directly to its destination\n", H(conn->id));
                        proxy_int(pkt);
                        free_pkt(pkt);
                        break;
                    case CONTROL:
                        if (DE_process_packet(pkt) == OK) {
                            proxy_int(pkt);
                        }
                        free_pkt(pkt);
                        break;
                    case INIT:
                    default:
                        /*! We are surely in the INIT state, so the HIH is initiating a connection to outside. We reset or control it */
                        if (deny_hih_init == 1) {
                            printdbg(
                                    "%s Packet from HIH at wrong state, so we reset\n", H(conn->id));
                            if (pkt->packet.ip->protocol == IPPROTO_TCP) {
                                reply_reset(pkt, pkt->conn->hih.iface);
                            }
                            switch_state(conn, DROP);
                            free_pkt(pkt);
                        } else {
                            printdbg(
                                    "%s Packet from HIH in a new connection, so we control it\n", H(conn->id));
                            switch_state(conn, CONTROL);
                            if (DE_process_packet(pkt) == OK) {
                                proxy_int(pkt);
                            }
                            free_pkt(pkt);
                        }
                        break;
                }
                break;

            case EXT:
            default:
                /*! Packet is from the external attacker (origin == EXT) */
                switch (conn->state) {
                    case INIT:
                    case DECISION:
                        //g_string_assign(conn->decision_rule, ";");
                        if (DE_process_packet(pkt) == OK) {
                            proxy_ext(pkt);
                        }

                        // Only store packets if there are backends
                        if (conn->target->back_handler_count > 0) {
                            store_pkt(conn, pkt);
                        } else {
                            free_pkt(pkt);
                        }
                        break;
                    case FORWARD:
                        forward_ext(pkt);
                        free_pkt(pkt);
                        break;
                    case PROXY:
                        printdbg(
                                "%s Packet from EXT proxied directly to its destination (PROXY)\n", H(conn->id));
                        proxy_ext(pkt);
                        free_pkt(pkt);
                        break;
                    case CONTROL:
                        printdbg(
                                "%s Packet from EXT proxied directly to its destination (CONTROL)\n", H(conn->id));
                        proxy_ext(pkt);
                        free_pkt(pkt);
                        break;
                    default:
                        free_pkt(pkt);
                        break;
                }
                break;
        }

        done:

        if(conn) {
            g_mutex_unlock(&conn->lock);
        }

        printdbg("%s de_thread end of loop\n", H(1));
    }
}

/*! main
 \brief process arguments, daemonize, init variables, create QUEUE handler and process each packet
 \param[in] argc, number of arguments
 \param[in] argv, table with arguments
 *
 \return 0 if exit with success, anything else if not */
int main(int argc, char *argv[]) {

    g_printerr("%s  v%s\n\n", banner, PACKAGE_VERSION);

    /*! parsing arguments */
    if (argc < 2) {
        usage(argv);
    }

    int argument;
    char *config_file_name = "";
    gboolean daemonize = FALSE;
    debug = FALSE;

    while ((argument = getopt(argc, argv, "sc:x:V:q:h:d?")) != -1) {
        switch (argument) {
            case 'c':
                /*! define configuration filename */
                config_file_name = optarg;
                break;
            case 'x':
                /*! send a shutdown request to honeybrid */
                g_printerr("Trying to shutdown honeybrid at pid %s\n", optarg);

                /*! convert argument to int */
                int pid = atoi(optarg);

                /*! check that process exists */
                if (-1 == kill(pid, 0)) {
                    errx(1, "%s: ERROR: Process does not exist", __func__);
                } else {
                    g_printerr("%s: Sending signal to halt engine\n", __func__);
                    /*! send signal USR1 to PID */
                    kill(pid, SIGQUIT);
                    exit(0);
                }
                break;
            case 'V':
                printf("Honeybrid Version %s\n", PACKAGE_VERSION);
                exit(0);
                break;
            case 's':
                g_printerr("Status informations not yet implemented\n");
                exit(-1);
                break;
                /*! \todo
                 add a signal handler to output statistics (figure out the correct file description for output...)
                 Statistics should include:
                 - version
                 - start time and duration
                 - packet processed:
                 * total
                 * TCP
                 * UDP
                 * Other
                 - connection processed:
                 * total
                 * INIT
                 * DECISION
                 * REPLAY
                 * FORWARD
                 * INVALID
                 * PROXY
                 - decision engine, for each module:
                 * rules loaded
                 * signature loaded
                 * connection redirected (MATCH)
                 * connection left alone (DOES NOT MATCH)
                 - errors
                 * NF_QUEUE restarts
                 * expected data
                 - top ports?
                 - top IP addresses?
                 */
            case 'd':
                g_printerr("Daemonizing honeybrid\n");
                daemonize = TRUE;
                break;
            case 'h':
            case '?':
            default:
                usage(argv);
                break;
                /* not reached */
        }
    }

    /*! initialize syslog */
    init_syslog(argc, argv);
    /*! initialize data structures */
    init_variables();
    /*! parse the configuration files and store values in memory */
    init_parser(config_file_name);
    /*! initialize signal handlers */
    init_signal();

    if (ICONFIG("max_packet_buffer") > 0) {
        max_packet_buffer = ICONFIG("max_packet_buffer");
    } else {
        max_packet_buffer = ULLONG_MAX;
    }

    deny_hih_init = ICONFIG("deny_hih_init");
    reset_ext = ICONFIG("reset_ext");

    output_t output = ICONFIG_REQUIRED("output");

    /* Start Honeybrid in the background if necessary */
    if (daemonize) {
        if (output != OUTPUT_STDOUT) {
            g_printerr("Honeybrid starting as background process\n");

            if (daemon(1, 0) < 0) {
                unlink(pidfile);
                err(1, "daemon");
            }
        } else {
            g_printerr("Output is defined as STDOUT, can't daemonize!\n");
        }
    }

    /*! Create PID file */
    pidfile = g_malloc0(
            snprintf(NULL, 0, "%s/honeybrid.pid",
                    CONFIG_REQUIRED("exec_directory")) + 1);
    sprintf((char *) pidfile, "%s/honeybrid.pid",
            CONFIG_REQUIRED("exec_directory"));
    unlink(pidfile);
    FILE *fp;
    if ((fp = fopen(pidfile, "w")) == NULL) {
        err(1, "fopen: %s", pidfile);
    }
    mainpid = getpid();
    fprintf(fp, "%li\n", mainpid);
    fclose(fp);
    chmod(pidfile, 0644);

    setlogmask(LOG_UPTO(LOG_INFO));

    /* Setting debug file */
    if (ICONFIG("debug") > 0) {

        debug = TRUE;

        if (CONFIG("debug_file")) {
            if ((fdebug = open_debug_log()) != -1) {

                if (!daemonize) {
                    g_printerr("Redirecting output to %s/%s.\n",
                            CONFIG_REQUIRED("log_directory"),
                            CONFIG_REQUIRED("debug_file"));
                    g_printerr(
                            "You should start with -d to daemonize Honeybrid!\n");
                }

                (void) dup2(fdebug, STDIN_FILENO);
                (void) dup2(fdebug, STDOUT_FILENO);
                (void) dup2(fdebug, STDERR_FILENO);
                if (fdebug > 2) {
                    close(fdebug);
                }
                syslog(LOG_INFO, "Starting Honeybrid.\n");
            } else {
                syslog(LOG_INFO, "file: %s", strerror(errno));
            }
        }
    }

    if (output == OUTPUT_MYSQL) {
#ifdef HAVE_MYSQL
        init_mysql_log();
#else
        errx(1, "%s: Honeybrid wasn't compiled with MySQL!", __func__);
#endif
    }

    if (output == OUTPUT_LOGFILES) {
        open_connection_log();
    }

    decision_threads = ICONFIG_REQUIRED("decision_threads");
    printdbg("%s Starting with %u decision threads.\n", H(0), decision_threads);

    de_threads = malloc(sizeof(GThread*) * decision_threads);
    de_queues = malloc(sizeof(GAsyncQueue*) * decision_threads);

    uint32_t i;
    for (i = 0; i < decision_threads; i++) {
        de_queues[i] = g_async_queue_new();
    }

    /*! init the Decision Engine threads */
    for (i = 0; i < decision_threads; i++) {
        if ((de_threads[i] = g_thread_new("de_thread", (void *) de_thread,
                GUINT_TO_POINTER(i))) == NULL) {
            errx(1, "%s: Unable to start the decision engine thread %i",
                    __func__, i);
        }
    }

    /*! initiate modules that can have only one instance */
    init_modules();

    /*! create the raw sockets for UDP/IP and TCP/IP */
    //TODO: switch to pcap_inject
    /*if (NOK == init_raw_sockets()) {
     errx(1, "%s: failed to create the raw sockets", __func__);
     }*/

    /*! create a thread for the management, cleaning stuffs and so on */
    if ((thread_clean = g_thread_new("cleaner", (void *) clean, NULL)) == NULL) {
        errx(1, "%s Unable to start the cleaning thread", __func__);
    } else {
        printdbg("%s Cleaning thread started\n", H(0));
    }

    init_pcap();
    wait_pcap();
    close_all();

    g_printerr("Honeybrid exited successfully.\n");
    exit(0);
}
