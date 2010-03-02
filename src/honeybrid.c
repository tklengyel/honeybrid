/*
 * $Id: honeybrid.c 714 2009-09-04 12:39:42Z robin $
 *
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
 * 	\section Requirements
 *
 * 	Dependencies:
 *	- linux kernel >= 2.6.18 & <=2.6.23
 * 	- libnetfilter-queue-dev & libnetfilter-queue1
 *	- libnfnetlink >= 0.0.25
 *	- libglib2.0-dev & libglib2.0-0
 *	- openssl
 *	- libssl-dev
 *	- libev
 *
 * 	\section Installation
 *
 *	Installation is defined in the INSTALL file.
 *
 */

/*!	\file honeybrid.c
	\brief Main File

	This is the main program file for Honeybrid. It creates a hook using LibNetfilter Queue
 	and, for each connection, maintain a stateful table.
 	It forward a packet to a determined destination and submit this packet to the decision engine.
 	When the decision engine decide to redirect a connection, this redirection engine replay the recorded
 	connection to its new destination and maintain it until its end.

	Packets needs to be redirected to the QUEUE destination using netfilter, this can be done using:
	# iptables -A INPUT -j QUEUE && iptables -A FORWARD -j QUEUE && iptables -A OUTPUT -j QUEUE

	filters can also be set up using the regulars iptables capabilities, it is also recommended to limit the redirections to TCP and UDP packets (just add the option -p to the iptables commands)

 	Dependencies:
 	- linux kernel >= 2.6.18 & <=2.6.23
 	- libnetfilter-queue-dev & libnetfilter-queue1
 	- libnfnetlink >= 0.0.25
	- libglib2.0-dev & libglib2.0-0

	Known problem: If the buffer size under linux is too low, the IPQ subsystem will exit with the error
 	"Failed to received netlink message: No buffer space available"
 	To avoid that, increase the buffer value in /proc/sys/net/core/rmem_default (and rmem_max)

	\Author J. Vehent, 2007
	\Author Thomas Coquelin, 2008
	\Author Robin Berthier, 2007-2009
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <malloc.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <glib.h>
#include <unistd.h>
#include <execinfo.h>

#include <ev.h>

#include "tables.h"
#include "honeybrid.h"
#include "netcode.h"
///#include "pcap_tool.h"
#include "log.h"
#include "decision_engine.h"
#include "modules.h"
//#include "rules.h"

#ifdef USE_LIBEV
struct nfq_handle	*h; 
struct ev_loop		*loop;
#endif

/*! usage function
 \brief print command line informations */
void usage(char **argv)
{
	g_printerr(	"Honeybrid version %s\n"
			"usage: %s <commands>\n\n"
			"where commands include:\n"
			"  -c <config_file>: start with config file\n"
			"  -x <pid>: halt the engine using its PID\n"
			"  -q <queuenum>: select a specific queue number for NF_QUEUE to listen to\n"
			"  -s: show status information\n"
			"  -h: print the help\n\n",
			VERSION,
			argv[0]);
	exit(1);
}

/*! print_trace
 * \brief Obtain a backtrace and print it to stdout. 
 */
void
print_trace (void)
{
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  printf ("Obtained %zd stack frames.\n", size);

  for (i = 0; i < size; i++)
     printf ("%s\n", strings[i]);

  free (strings);
}


/*! close_thread
 \brief Function that waits for thread to close themselves */
int close_thread()
{

	threading = NOK;

	#ifndef USE_LIBEV
	g_printerr("%s: Waiting for thread_clean to terminate\n", __func__);
	g_thread_join(thread_clean);
	#endif

	#ifdef DE_THREAD
	g_printerr("%s: Waiting for thread_de to terminate\n", __func__);
	g_thread_join(thread_de);
	#endif
	/*
	g_printerr("%s:Waiting for thread_log to terminate\n", __func__);
	g_thread_join(thread_log);
	*/
	return 0;
}

/*! free_table
 \brief Function to free memory in the different table created */
int free_table(gchar *key, gchar *value, gpointer data)
{
	if (key != NULL)
		g_free (key);
	if (value != NULL)
		g_free (value);
	return TRUE;

}

/*! free_hash
 \brief Function to free memory in the different subhash created */
int free_hash(gchar *key, GHashTable *value, gpointer data)
{
	if (key != NULL && value != NULL) {
		g_hash_table_foreach_remove(value, (GHRFunc) free_table, NULL);
                g_hash_table_destroy(value);
	}
	return TRUE;

}

/*! close_hash function
 \brief Destroy the different hashes used by honeybrid */
int close_hash()
{
	/*! Destroy hash tables 
	 */
	if (log_table != NULL) {
		g_printerr("%s: Destroying table log_table\n", __func__);
		g_hash_table_foreach_remove(log_table, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(log_table);
	}

	/* \todo TODO deprecated
	if (low_redirection_table != NULL) {
		g_printerr("%s: Destroying table low_redirection_table\n", __func__);
		g_hash_table_foreach_remove(low_redirection_table, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(low_redirection_table);
	}


	//if (low_honeypot_addr != NULL) {	//DEPRECATED
		g_print("close_hash():\tDestroying table low_honeypot_addr\n");
		g_hash_table_foreach_remove(low_honeypot_addr, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(low_honeypot_addr);
	//}

	if (high_honeypot_addr != NULL) {
		g_print("close_hash():\tDestroying table high_honeypot_addr\n");
		g_hash_table_foreach_remove(high_honeypot_addr, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(high_honeypot_addr);
	}
	*/

	if (high_redirection_table != NULL) {
		g_printerr("%s: Destroying table high_redirection_table\n", __func__);
		g_hash_table_foreach_remove(high_redirection_table, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(high_redirection_table);
	}

	if (DE_rules != NULL) {
		/*! this table generates invalid free error in valgrind
		 */
		/*! and also a seg fault...
		g_print("close_hash():\tDestroying table DE_rules\n");
		g_hash_table_foreach_remove(DE_rules, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(DE_rules);
		*/
	}

	if (config != NULL) {
		g_printerr("%s: Destroying table config\n", __func__);
		g_hash_table_foreach_remove(config, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(config);
	}
	/*
	if (module != NULL) {
		g_printerr("%s: Destroying table module\n", __func__);
		g_hash_table_foreach(module, (GHFunc) free_hash, NULL);
		//g_hash_table_foreach_remove(module, (GHRFunc) free_table, NULL);
		g_hash_table_destroy(module);
	}
	*/

	return 0;
}

/*! close_conn_tree function
 \brief Function to free memory taken by conn_tree */
int close_conn_tree()
{
	/*! clean the memory
	 * traverse the B-Tree to remove the singly linked lists and then destroy the B-Tree
	 */
	int delay = 0;
	entrytoclean = g_ptr_array_new();

        /*! call the clean function for each value, delete the value if TRUE is returned */
        g_tree_traverse( conn_tree,(GHRFunc) expire_conn, G_IN_ORDER, &delay );

        /*! remove each key listed from the btree */
        g_ptr_array_foreach(entrytoclean,(GFunc) free_conn, NULL);

        /*! free the array */
        g_ptr_array_free(entrytoclean, TRUE);

	//g_tree_traverse(conn_tree,(GHRFunc) clean_entry, G_IN_ORDER, NULL );
	g_tree_destroy(conn_tree);

	/*! close log file */
	close_connection_log();

	return 0;
}

void
free_target(struct target *t, gpointer user_data)
{
	g_free(t->filter);
	g_free(t->front_handler);
	g_free(t->back_handler);
	if (t->front_rule != NULL)
		g_free(t->front_rule);
	if (t->back_rule != NULL)
		g_free(t->back_rule);
	if (t->control_rule != NULL)
		g_free(t->control_rule);
	g_free(t);
}

/*! close_target
 \brief destroy global structure "targets" when the program has to quit */
int
close_target(void)
{
	g_printerr("%s: Destroying targets\n", __func__);
	g_ptr_array_foreach(targets, (GFunc) free_target, NULL);
	g_ptr_array_free(targets, TRUE);
	return OK;
}

/*! close_all
 \brief destroy structures and free memory when the program has to quit */
void
close_all(void)
{
	/*! delete lock file (only if the process ran as a daemon) */
	if ( ICONFIG("output") != 2 )
        {
		if (unlink(PIDFILE) < 0) 
			g_printerr("%s: Error when removing lock file\n", __func__);
	}

	/*! wait for thread to close */
	if (close_thread() < 0) 
		g_printerr("%s: Error when waiting for threads to close\n", __func__);

	/*! delete hashes */
	if (close_hash() < 0) 
		g_printerr("%s: Error when closing hashes\n", __func__);

	if (close_target() <0)
		g_printerr("%s: Error when closing targets\n", __func__);

	/*! delete conn_tree */
	if (close_conn_tree() < 0) 
		g_printerr("%s: Error when closing conn_tree\n", __func__);

	closelog();
}

/*! term_signal_handler
 *
 \brief called when the program receive a signal that should close the program, free memory and delete lock file
 *
 \param[in] signal_nb: number of the signal
 \param[in] siginfo: informations regarding to the signal
 \param[in] context: NULL */
int 
term_signal_handler(int signal_nb, siginfo_t * siginfo, void *context)
{
	g_printerr("%s: Signal %d received, halting engine\n", __func__, signal_nb);
	#ifdef DEBUG
	g_printerr("* Signal number:\t%d\n", siginfo->si_signo);
	g_printerr("* Signal code:  \t%d\n", siginfo->si_code);
	g_printerr("* Signal error: \t%d '%s'\n", siginfo->si_errno, strerror(siginfo->si_errno));
	g_printerr("* Sending pid:  \t%d\n", siginfo->si_pid);
	g_printerr("* Sending uid:  \t%d\n", siginfo->si_uid);
	g_printerr("* Fault address:\t%p\n", siginfo->si_addr);
	g_printerr("* Exit value:   \t%d\n", siginfo->si_status);
	/*! print backtrace */
	print_trace();
	#endif
	running = NOK;	/*! this will cause the queue loop to stop */
	/*
	close_all();
	g_printerr("%s: Halted\n", __func__);
	exit(signal_nb);
	*/
	#ifdef USE_LIBEV
	ev_unloop (loop, EVUNLOOP_ALL);
	#endif
	return 0;
}


/*! switch_clean
 \brief call the packet cleaner */
void 
switch_clean()
{
	clean();
}

/*! init_syslog
 \brief initialize syslog logging */
static void
init_syslog(int argc, char *argv[])
{
        int options, i;
        char buf[MAXPATHLEN];

#ifdef LOG_PERROR
        options = LOG_PERROR|LOG_PID|LOG_CONS;
#else
        options = LOG_PID|LOG_CONS;
#endif
        openlog("honeybrid", options, LOG_DAEMON);

        /* Create a string containing all the command line
         * arguments and pass it to syslog:
         */

        buf[0] = '\0';
        for (i = 1; i < argc; i++) {
                if (i > 1 && g_strlcat(buf, " ", sizeof(buf)) >= sizeof(buf))
                        break;
                if (g_strlcat(buf, argv[i], sizeof(buf)) >= sizeof(buf))
                        break;
        }

        syslog(LOG_NOTICE, "started with %s", buf);
}

/*! parse_config
 \brief Configuration parsing function, read the configuration from a specific file 
  and parse it into a hash table or other tree data structures using Bison/Flex
*/
void
init_parser(char *filename)
{
	FILE *fp = fopen(filename, "r");
	if (!fp)
		err(1,"fopen");

	//extern int yydebug;
	//yydebug = 1;
	yyin=fp;
	yyparse();	

	fclose(fp);

	g_printerr("Parsing done\n");
}

void
init_variables()
{
	/*! create the hash table to store the config */
	if (NULL == (config = g_hash_table_new(g_str_hash, g_str_equal))) 
		errx(1,"%s: Fatal error while creating config hash table.\n", __func__);

	/*! create the array of pointer to store the target information */
	if (NULL == (targets = g_ptr_array_new()))
		errx(1,"%s: Fatal error while creating targets pointer of array.\n", __func__);

	/*! create the hash table to store module information */
	if (NULL == (module = g_hash_table_new(g_str_hash, g_str_equal))) 
		errx(1,"%s: Fatal error while creating module hash table.\n", __func__);

	/*! create the hash table for the log engine */
	if (NULL == (log_table = g_hash_table_new(g_str_hash, g_str_equal))) 
		errx(1,"%s: Fatal error while creating log_table hash table.\n", __func__);

	/*! create the hash table for the redirection table \todo DEPRECATED
	if (NULL == (low_redirection_table = g_hash_table_new(g_str_hash, g_str_equal))) 
		errx(1,"%s: Fatal error while creating redirection_table hash table.\n", __func__);
	*/
	/*! create the hash table for the LIH list \todo DEPRECATED
	if (NULL == (low_honeypot_addr = g_hash_table_new(g_int_hash, g_int_equal))) 
		errx(1,"%s: Fatal error while creating low_honeypot_addr hash table.\n", __func__);
	*/
	/*! create the hash table for the HIH list \todo DEPRECATED
	if (NULL == (high_honeypot_addr = g_hash_table_new(g_int_hash, g_int_equal))) 
		errx(1, "%s: Error while creating high_honeypot_addr hash table.\n", __func__);
	*/

	/*! create the hash table to store the pointers to the boolean execution trees */
	if (NULL == (DE_rules = g_hash_table_new(g_str_hash, g_str_equal))) 
		errx(1, "%s: Fatal error while creating DE_mod hash table.\n", __func__);

	/*! init the log singly linked list */
	log_list = NULL;

	/*! init the connection id counter */
	c_id = 10;

	#ifdef DE_THREAD
	/*! init DE_queue */
	DE_queue = NULL;
	#endif

	/*! Enable data processing */
	running = OK;

	/*! init the security locks */
	g_static_rw_lock_init( &rwlock );
	#ifdef DE_THREAD
	g_static_rw_lock_init( &DE_queue_lock );
	#endif
	//g_static_rw_lock_init( &loglock );

	/*! g_tree_new_full - create the main B-Tree to store meta informations of active connections
	 *
	\param[in] GCompareDataFunc:  function to compare 2 entries, we use strcmp
	\param[in] GDestroyNotify:  function called to destroy a key
	\param[in] GDestroyNotify:  function called to destroy a value
	\return  a new GTree.
	 */
	if (NULL == (conn_tree =
		   g_tree_new_full((GCompareDataFunc)strcmp,NULL,(GDestroyNotify)g_free,(GDestroyNotify)g_free))
	   ) {
		errx(1, "%s: Fatal error while creating conn_tree.\n", __func__);
	}
}

/*! process_packet
 *
 \brief Function called for each received packet, this is the core of the redirection engine
 \param[in] tb a Netfilter Queue structure that contain both the packet and the metadatas
 \return statement = 1 if the packet should be accepted or 0 if the packet has to be dropped. Default is to drop. */
static u_int32_t 
process_packet(struct nfq_data *tb)
{
	/*! We create a new temporary connection structure */
	struct conn_struct conn_init;
        conn_init.state = INVALID;	/* by default the connection is invalid */
        conn_init.id = 0;
        struct conn_struct * conn = &conn_init;

	struct pkt_struct * pkt = (struct pkt_struct *) malloc(sizeof(struct pkt_struct)); /* \todo TODO: check that it's correctly freed */
	int statement = 0;		/* by default we reject this packet */
	char *nf_packet;
	struct in_addr in;

	/*! extract ip header from packet payload */
	int size;
	size = nfq_get_payload(tb, &nf_packet);
	if(size < 0) {
		return statement = 0;
	}

	in.s_addr=((struct iphdr*)nf_packet)->saddr;

	g_printerr("%s** NEW packet from %s %s, %d bytes **\n", 
		H(conn->id), 
		inet_ntoa(in), 
		lookup_proto(((struct iphdr*)nf_packet)->protocol),
		size);	

	/*! check if protocol is invalid (not TCP or UDP) */
	if ((((struct iphdr*)nf_packet)->protocol != 6) && (((struct iphdr*)nf_packet)->protocol != 17)) {
		g_printerr("%s Incorrect protocol: %d, packet dropped\n", H(conn->id), (((struct iphdr*)nf_packet)->protocol));
		return statement = 0;
	}

	/*! Initialize the packet structure (into pkt) and find the origin of the packet */
	if (init_pkt(nf_packet, pkt) == NOK) {
		g_printerr("%s Packet structure couldn't be initialized, packet dropped\n", H(conn->id));
		return statement = 0;
	}

	/*! Initialize the connection structure (into conn) and get the state of the connection */
	if (init_conn(pkt, &conn) == NOK) {
		g_printerr("%s Connection structure couldn't be initialized, packet dropped\n", H(conn->id));
		return statement = 0;
	}

	#ifdef DEBUG
	g_printerr("%s Origin: %s %s, %i bytes\n", 
		H(conn->id), 
		lookup_origin(pkt->origin),
		lookup_state(conn->state), 
		pkt->data);
	#endif
	
	/*! Check that there was no problem getting the current connection structure
	 *  and make sure the STATE is valid */
	if (((conn->state < INIT)
		&& (pkt->origin == EXT))
		|| (conn->state < INVALID)) {	
		///INIT == 1, INVALID == 0 and NOK == -1
		g_printerr("%s Packet not from a valid connection %s\n",
			H(conn->id),
			inet_ntoa(in));
		#ifdef RST_EXT
		if(pkt->packet.ip->protocol==0x06)
			reply_reset( pkt->packet );
		#endif
		free_pkt(pkt);
		return statement = 0;
	}

	if ( conn->state == DROP ) {
		g_printerr("%s This connection is marked as DROPPED %s\n",
			H(conn->id),
			inet_ntoa(in));
		#ifdef RST_EXT
			if(pkt->packet.ip->protocol==0x06)
				reply_reset( pkt->packet );
		#endif
		free_pkt(pkt);
		return statement = 0;
	}

	switch( pkt->origin ) {
	/*! Packet is from the low interaction honeypot */
	case LIH:
		switch( conn->state ) {
		case INIT:
			if(pkt->packet.ip->protocol == 0x06 && pkt->packet.tcp->syn!=0) {
				conn->hih.lih_syn_seq = ntohl(pkt->packet.tcp->seq);
			}
			store_pkt(conn, pkt);
			//conn->state = CONTROL;	
			//switch_state(conn, CONTROL); //Now it's when the connection is created that the state is on CONTROL for LIH
			statement = 1;	//DE_process_packet(pkt);	/*! For now, we don't analyze packets from LIH */
			break;
		case DECISION:
			if(pkt->packet.ip->protocol == 0x06 && pkt->packet.tcp->syn!=0) {
				conn->hih.lih_syn_seq = ntohl(pkt->packet.tcp->seq);
			}
			store_pkt(conn, pkt);
			statement = 1;	//DE_process_packet(pkt);	/*! For now, we don't analyze packets from LIH */
			break;		
		case PROXY:
			#ifdef DEBUG
			g_printerr("%s Packet from LIH proxied directly to its destination\n", H(conn->id));
			#endif
			statement = 1;
			break;
		case CONTROL:
			if(pkt->packet.ip->protocol == 0x06 && pkt->packet.tcp->syn!=0) {
				conn->hih.lih_syn_seq = ntohl(pkt->packet.tcp->seq);
			}
			store_pkt(conn, pkt);
			statement = DE_process_packet(pkt);
			break;
		default:
			g_printerr("%s Packet from LIH at wrong state => reset %s\n", H(conn->id), inet_ntoa(in));
			if(pkt->packet.ip->protocol==0x06)
				reply_reset( pkt->packet );
			free_pkt(pkt);
			break;
		}
		break;

	/*! Packet is from the high interaction honeypot */
	case HIH:
		switch( conn->state ) {
		case REPLAY:
			/*! push the packet to the synchronization list in conn_struct */
			if(pkt->packet.ip->protocol == 0x06 && pkt->packet.tcp->syn == 1) {
				conn->hih.delta = ~ntohl(pkt->packet.tcp->seq) + 1 + conn->hih.lih_syn_seq;
			}
			replay(conn, pkt );	
			break;
		case FORWARD:
			forward(pkt );
			free_pkt(pkt);
			break;		
		/*! This one should never occur because PROXY are only between EXT and LIH... but we never know! */
		case PROXY:
			#ifdef DEBUG
			g_printerr("%s Packet from EXT proxied directly to its destination\n", H(conn->id));
			#endif
			statement = 1;
			break;
		case CONTROL:
			statement = DE_process_packet(pkt);
			break;
		default:
			/*! We are surely in the INIT state, so the HIH is initiating a connection to outside. We reset or control it */
			if (RESET_HIH > 0) {	
				g_printerr("%s Packet from HIH at wrong state, so we reset %s\n", H(conn->id), inet_ntoa(in));
				if(pkt->packet.ip->protocol==0x06) {
					reply_reset( pkt->packet );
				}
				statement = 0;
				//conn->state = DROP;
				switch_state(conn, DROP);
				free_pkt(pkt);
			} else {
				g_printerr("%s Packet from HIH at wrong state, so we control it (%s)\n", H(conn->id), inet_ntoa(in));
				//conn->state = CONTROL;
				switch_state(conn, CONTROL);
				statement = DE_process_packet(pkt);
			}
			break;
		}
			break;

	/*! Packet is from the external attacker (origin == EXT) */
	default:
		switch( conn->state ) {
		case INIT:
			store_pkt(conn, pkt);
			//conn->state = DECISION;
			g_string_assign(conn->decision_rule, ";");
			statement = DE_process_packet(pkt);

			break;
		case DECISION:
			store_pkt(conn, pkt);
			statement = DE_process_packet(pkt);
			break;
		case FORWARD:
			forward(pkt );
			free_pkt(pkt);
			break;		
		case PROXY:
			#ifdef DEBUG
			g_printerr("%s Packet from EXT proxied directly to its destination\n", H(conn->id));
			#endif
			statement = 1;
			break;
		case CONTROL:
			#ifdef DEBUG
			g_printerr("%s Packet from EXT proxied directly to its destination\n", H(conn->id));
			#endif
			statement = 1;
			break;
		default:
			store_pkt(conn, pkt);
			break;
		}
		break;
	}

	return statement;
}


/*! q_cb
 *
 \brief Callback function launched by the netfilter queue handler each time a packet is received
 * */
static int q_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	/*! get packet id */
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	int id = ntohl(ph->packet_id);

	/*! launch process function */
	u_int32_t statement = process_packet(nfa);

	if(statement == 1) {
		/*! nfq_set_verdict_mark
		\brief set a decision NF_ACCEPT or NF_DROP on the packet and put a mark on it
		 *
		\param[in] qh netfilter queue handle obtained by call to nfq_create_queue
		\param[in] id id of the packet
		\param[in] verdict NF_ACCEPT or NF_DROP
		\param[in] mark netfilter mark value to mark packet with (don't forget to convert it in network order)
		\param[in] data_len (optional) number of bytes of data pointer by buf
		\param[in] buf pointer to data buffer
		 *
		\return 0 on success, non-zore on failure */

		/*! ACCEPT the packet if the statement is 1 */
		return nfq_set_verdict_mark(qh, id, NF_ACCEPT, htonl(0), 0, NULL);
	} else {
		/*! DROP the packet if the statement is 0 (or something else than 1) */
		return nfq_set_verdict_mark(qh, id, NF_DROP, htonl(1), 0, NULL);
	}

}

#ifndef USE_LIBEV
/*! netlink loop
 \brief Function to create and maintain the NF_QUEUE loop
 \param[in] queuenum the queue identifier
 \return status
 */
short int netlink_loop(unsigned short int queuenum)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        struct nfnl_handle *nh;
        int fd, rv, watchdog;
        char buf[BUFSIZE];

	running = OK;

        h = nfq_open();
        if (!h) 
		errx(1,"%s Error during nfq_open()", __func__);	

        if (nfq_unbind_pf(h, AF_INET) < 0) 
		errx(1,"%s Error during nfq_unbind_pf()", __func__);	

        if (nfq_bind_pf(h, AF_INET) < 0) 
		errx(1,"%s Error during nfq_bind_pf()", __func__);	

	syslog(LOG_INFO, "NFQUEUE: binding to queue '%hd'\n", queuenum);

        qh = nfq_create_queue(h,  queuenum, &q_cb, NULL);
        if (!qh) 
		errx(1,"%s Error during nfq_create_queue()", __func__);	

        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, PAYLOADSIZE) < 0) 
		errx(1,"%s Can't set packet_copy mode", __func__);	

        nh = nfq_nfnlh(h);
        fd = nfnl_fd(nh);

	watchdog = 0;
	while (running == OK) {
		memset(buf, 0, sizeof(buf));
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv < 0) {
			g_printerr("%s Error %d: recv() returned %d '%s'\n", H(0), errno, rv, strerror(errno));
			watchdog++;
			if (watchdog > 100) {
				g_printerr("%s Error: too many consecutive failures, giving up\n", H(0));
                                running = NOK;
			}
		} else {
			nfq_handle_packet(h, buf, rv);
			if (watchdog > 0) {
				watchdog = 0;
			}
		}
		/*
	        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0 && running == OK) {
        	        nfq_handle_packet(h, buf, rv);
			if (watchdog > 0)
				watchdog = 0;
	        }
		if (running == OK) {
			g_printerr("%s Error: recv() returned negative value: %d\n", H(0), rv);
			g_printerr("%s Errno: %d, message: '%s'\n", H(0), errno, strerror(errno));
			watchdog++;
			if (watchdog > 100) {
				g_printerr("%s Error: too many consecutive failures, giving up\n", H(0));
				running = NOK;
			}
		}	
		*/
	}

	syslog(LOG_INFO, "NFQUEUE: unbinding from queue '%hd' (running: %d, rv: %d)\n", queuenum, running, rv);
        nfq_destroy_queue(qh);
        nfq_close(h);
        return(0);	
}

#else

static void
nfqueue_ev_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	int rv;
        char buf[BUFSIZE];

	rv = recv(w->fd, buf, sizeof(buf), 0);
	if (rv >= 0 && running == OK) {
	        //nfq_handle_packet((struct nfq_handle *)w->data, buf, rv);
	        nfq_handle_packet(h, buf, rv);
	}
}

/*! init_nfqueue
 *
 \brief Function to create the NF_QUEUE loop
 \param[in] queuenum the queue identifier
 \return file descriptor for queue
 */
int 
//init_nfqueue(struct nfq_handle *h, struct nfq_q_handle *qh, unsigned short int queuenum)
init_nfqueue(struct nfq_q_handle *qh, unsigned short int queuenum)
{
        struct nfnl_handle *nh;

	running = OK;

        h = nfq_open();
        if (!h) 
		errx(1,"%s Error during nfq_open()", __func__);	

        if (nfq_unbind_pf(h, AF_INET) < 0) 
		errx(1,"%s Error during nfq_unbind_pf()", __func__);	

        if (nfq_bind_pf(h, AF_INET) < 0) 
		errx(1,"%s Error during nfq_bind_pf()", __func__);	

	syslog(LOG_INFO, "NFQUEUE: binding to queue '%hd'\n", queuenum);

        qh = nfq_create_queue(h,  queuenum, &q_cb, NULL);
        if (!qh) 
		errx(1,"%s Error during nfq_create_queue()", __func__);	

        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, PAYLOADSIZE) < 0) 
		errx(1,"%s Can't set packet_copy mode", __func__);	

        nh = nfq_nfnlh(h);

        return(nfnl_fd(nh));	
}

static void
//close_nfqueue(struct nfq_handle *h, struct nfq_q_handle *qh, unsigned short int queuenum)
close_nfqueue(struct nfq_q_handle *qh, unsigned short int queuenum)
{
	syslog(LOG_INFO, "NFQUEUE: unbinding from queue '%hd' (running: %d)\n", queuenum, running);
        nfq_destroy_queue(qh);
        nfq_close(h);
}

static void
timeout_clean_cb (EV_P_ ev_timer *w, int revents)
{
     //g_printerr("%s timeout reach for ev_timer!\n", H(0));
	clean();
}
#endif

//End Test

/*! init_signal
 \brief installs signal handlers
 \return 0 if exit with success, anything else if not */
void 
init_signal()
{
	/*! Install terminating signal handler: */
	struct sigaction sa_term;
	memset(&sa_term, 0, sizeof sa_term);

	sa_term.sa_sigaction = (void *)term_signal_handler;
	sa_term.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigfillset(&sa_term.sa_mask);

	/*! SIGHUP*/
	if (sigaction(SIGHUP, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGHUP", __func__);

	/*! SIGINT*/
	if (sigaction(SIGINT, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGINT", __func__);

	/*! SIGQUIT*/
	if (sigaction(SIGQUIT, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGQUIT", __func__);

	/*! SIGILL*/
	if (sigaction(SIGILL, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGILL", __func__);

	/*! SIGSEGV*/
	if (sigaction(SIGSEGV, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGSEGV", __func__);

	/*! SIGTERM*/
	if (sigaction(SIGTERM, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGTERM", __func__);
	
	/*! SIGBUS*/
	if (sigaction(SIGBUS, &sa_term, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGBUS", __func__);

	/*! ignore signals: */
	struct sigaction sa_ignore;
	memset(&sa_ignore, 0, sizeof sa_ignore);
	sa_ignore.sa_handler = SIG_IGN;
	sigfillset(&sa_ignore.sa_mask);
	
	/*! SIGABRT*/
	if (sigaction(SIGABRT, &sa_ignore, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGABRT", __func__);

	/*! SIGALRM*/
	if (sigaction(SIGALRM, &sa_ignore, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGALRM", __func__);

	/*! SIGUSR2*/
	if (sigaction(SIGUSR2, &sa_ignore, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGUSR2", __func__);

	/*! SIGPOLL*/
	if (sigaction(SIGPOLL, &sa_ignore, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGPOLL", __func__);

	/*! rotate logs: */
	struct sigaction sa_rotate_log;
	memset(&sa_rotate_log, 0, sizeof sa_rotate_log);

	sa_rotate_log.sa_sigaction = (void *)rotate_connection_log;
	//sa_rotate_log.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sa_rotate_log.sa_flags = SA_RESTART;
	sigfillset(&sa_rotate_log.sa_mask);

	/*! SIGUSR1*/
	if (sigaction(SIGUSR1, &sa_rotate_log, NULL) != 0) 
		errx(1, "%s: Failed to install sighandler for SIGUSR1", __func__);
}


/*! main
 \brief process arguments, daemonize, init variables, create QUEUE handler and process each packet
 \param[in] argc, number of arguments
 \param[in] argv, table with arguments
 *
 \return 0 if exit with success, anything else if not */
int 
main(int argc, char *argv[])
{
	int argument;
	char *config_file_name = "";
	threading = OK;
	FILE *fp;
	int fdebug;

	unsigned short int queuenum=0;
	#ifdef USE_LIBEV
	//struct nfq_handle *h; 
	struct nfq_q_handle *qh;
	int my_nfq_fd;
	#endif

	#ifdef DEBUG
	g_printerr("\n\n");
	#endif
        g_printerr("Honeybrid V%s Copyright (c) 2007-2009 University of Maryland\n", 
		VERSION);

	/*! parsing arguments */
	if(argc < 2)
		usage(argv);
	while ((argument = getopt(argc, argv, "sc:x:V:q:h?")) != -1)
	{
		switch (argument)
		{
			case 'c':
				/*! define configuration filename */
				config_file_name = optarg;
				break;
			case 'x':
				/*! send a shutdown request to honeybrid */
				g_printerr( "Trying to shutdown honeybrid at pid %s\n",optarg);

				/*! convert argument to int */
				int pid = atoi(optarg);

				/*! check that processus exists */
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
				printf("Honeybrid Version %s\n", VERSION);
					exit(0);
				break;
			case 'q':
				queuenum=(unsigned short int)atoi(optarg);
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
			case 'h' :
			case '?' :
			default :
				usage(argv);
				/* not reached */
		}
	}

	/*! init glib thread system */
	if (!g_thread_supported ()) g_thread_init (NULL); /*! \todo check if threads are correctly freed */
	/*! initialize signal handlers */
	init_signal();
	/*! initialize syslog */
	init_syslog(argc, argv);
	/*! initialize data structures */
	init_variables();

	/*! parse the configuration files and store values in memory */
	init_parser(config_file_name);

	/*! Create PID file, we might not be able to remove it */
        unlink(PIDFILE);
        if ((fp = fopen(PIDFILE, "w")) == NULL) {
                err(1, "fopen");
	}

        /* Start Honeybrid in the background if necessary */
        if (ICONFIG("output") != 2) {
                setlogmask(LOG_UPTO(LOG_INFO));

                g_printerr("Honeybrid starting as background process\n");
                if (daemon(1, 0) < 0) {
                        unlink(PIDFILE);
			err(1, "daemon");
                } else {
			/*! reopening file descriptor now that we're a daemon */
			//if ((fdebug = open("/tmp/honeybrid.debug", O_CREAT | O_RDWR, 0744)) != -1) {
			if ((fdebug = open_debug_log()) != -1) {
		                (void)dup2(fdebug, STDIN_FILENO);
		                (void)dup2(fdebug, STDOUT_FILENO);
        		        (void)dup2(fdebug, STDERR_FILENO);
	                	if (fdebug > 2)
                	        	(void)close (fdebug);
				syslog(LOG_INFO,"done");
		        } else {
				syslog(LOG_INFO,"file: %s", strerror(errno));
			}
		}
        }

        fprintf(fp, "%d\n", getpid());
        fclose(fp);

        chmod(PIDFILE, 0644);
	mainpid = getpid();
	open_connection_log();

	#ifdef DE_THREAD
	/*! init the Decision Engine thread */
	if( ( thread_de = g_thread_create_full ((void *)DE_submit_packet, NULL, 0, TRUE, TRUE, 0, NULL)) == NULL) 
		errx(1, "%s: Unable to start the decision engine thread", __func__);
	else
		g_printerr("%s: Decision engine thread started\n", __func__);
	#endif

	/*! initiate outgoing connection control => no longer needed
	init_control(); */
	/*! initiate decision engine modules => done automatically in rules.y, except for init_mod_hash: */
	init_modules(); 

	/*! create the two raw sockets for UDP/IP and TCP/IP */
	init_raw_sockets();
	if(tcp_rsd == 0 || udp_rsd == 0) 
		errx(1, "%s: failed to create the raw sockets", __func__);



	#ifdef USE_LIBEV
		loop = ev_default_loop(0);
		//Watcher for cleaning conn_tree every 10 seconds:
		ev_timer  timeout_clean_watcher;
		ev_timer_init  (&timeout_clean_watcher, timeout_clean_cb, 10., 10.);
		ev_timer_start (loop, &timeout_clean_watcher);
		/*! Watcher for processing packets received on NF_QUEUE: */
		my_nfq_fd = 	init_nfqueue(qh, queuenum);
		ev_io		queue_watcher;
		ev_io_init  	(&queue_watcher, nfqueue_ev_cb, my_nfq_fd, EV_READ);
		ev_io_start 	(loop, &queue_watcher);
		g_printerr("%s Starting ev_loop\n", H(0));
		//ev_loop (loop, EVLOOP_NONBLOCK);
		ev_loop(loop, 0);
		/*! To be moved inside close_all() */
		close_nfqueue(qh, queuenum);
	#else
		/*! create a thread for the management, cleaning stuffs and so on */
		if( ( thread_clean = g_thread_create_full ((void *)switch_clean, NULL, 0, TRUE, TRUE,G_THREAD_PRIORITY_LOW, NULL)) == NULL) {
			errx(1, "%s: Unable to start the cleaning thread", __func__);
		} else {
			g_printerr("%s: Cleaning thread started\n", __func__);
		}
		/*! Starting the nfqueue loop to start processing packets */
		g_printerr("%s Starting netlink_loop\n", H(0));
        	netlink_loop(queuenum);
		/*! sometimes netlink_loop exits by itself... so we have to restart it 
		int i = 0;
		while (running == OK) {
	        	netlink_loop(queuenum);
			g_printerr("%s Netlink loop exited (%d times so far)\n", H(0), i);
			g_usleep(1000000);	
			i++;
			if (i>100) {
				g_printerr("%s Reached maximum of 100 restarts... giving up\n", H(0));
				running = NOK;
			}
		}
		*/
	#endif

	close_all();
        g_printerr("%s: Halted\n", __func__);
	exit(0);

	/* \todo to include in programmer documentation:
	//What we should use to log messages:
		//For debugging:
		g_printerr("%smessage\n", H(30));

		//For processing information:
		syslog(LOG_INFO,"message");

		//For critical warning
		warn("open");
		warnx("%s message", __func__);

		//For fatal error
		err("fopen");
		errx(1,"%s message", __func__);

	*/
}
