/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <jvehent@umd.edu> for the University of Maryland)
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
 *
 * 	\section Installation
 *
 *	Installation is defined in the INSTALL file.
 *
 */

/*!	\file main.c
	\brief Main File

	This is the main program file for the Redirection engine. It creates a hook using LibNetfilter Queue
 	and, for each connection, maintain a stateful table.
 	It forward a packet to a determined destination and submit this packet to the decision engine.
 	When the decision engine decide to redirect a connection, this redirection engine replay the recorded
 	connection to its new destination and maintain it until its end.

	Packets needs to be redirected to the QUEUE destination using netfilter, this can be done using:
	# iptables -A INPUT -j QUEUE && iptables -A FORWARD -j QUEUE && iptables -A OUTPUT -j QUEUE

	filters can also be setted up using the regulars iptables capabilities, it is also recommended to limit the redirections to TCP and UDP packets (just add the option -p to the iptables commands)

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

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <malloc.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <glib.h>

#include "tables.h"
#include "netcode.h"
///#include "pcap_tool.h"
#include "log.h"
#include "decision_engine.h"
#include "modules.h"




/*! writing lock initialization
 */
#define G_STATIC_RW_LOCK_INIT { G_STATIC_MUTEX_INIT, NULL, NULL, 0, FALSE, 0, 0 }


/*! Multi-thread safe mode
 */
#define G_THREADS_ENABLED


/*!
  \def DESTSIZE
 *
 * max size of an IP address (4*3 = 12 + 3 dots = 15)
 */
#define DESTSIZE 15

/*!
  \def CONF_MAX_LINE
 *
 * max size of a line in the configuration file
 */
#define CONF_MAX_LINE 1024

/*!
 \def h
 *
 * A pointer to the netfilter queue handle
 */
struct nfq_handle *h;

/*!
 \def qh
 *
 * A queue handle
 */
struct nfq_q_handle *qh;

/*!
 \def nh
 *
 * Netlink handle associated with a queue connection handle
 */
struct nfnl_handle *nh;

/*!
 \def fd
 *
 * File descriptor to the netlink connection associated with a queue connection handle
 */
FILE *fd;

/*!
 \def received
 *
 * An integer that store the data size received through the queue
 */
int received;

/*!
 \def buf
 *
 * Buffer for incoming packets
 */
unsigned char buf[BUFSIZE];


/*!
 \def running
 *
 * Init value: OK
 * Set to NOK when honeybrid is stopping
 * It is used to stop processing new data when honeybrid is stopping
 */
int running;

//! Usage function, print command line informations
/*!
 */
void usage(char **argv)
{
	g_print(	"================================\n"
			"=	honeybrid Redirector	=\n"
			"=	     version 0.7	=\n"
			"================================\n\n"
			"usage: %s <commands>\n\n"
			"commands:\n"
			"\t-c <config_file>: start with config file\n"
			"\t-x <pid>: halt the engine using its PID\n"
			"\t-s: show status informations\n"
			"\t-h: print the help\n\n",
			argv[0]);
}


/*! die function
 \brief Destroy the structure when the program exit
 */
void die()
{
	if(qh)
		nfq_destroy_queue(qh);
	nfq_close(h);
	nfq_unbind_pf(h, AF_INET);

	L("die():\tNetfilter Queue handling error",NULL,1,1);

	exit(-1);
}

/*! clean_entry
 \brief free all the datas stored in an entry of the B-Tree
 *
 \return FALSE, to continue to traverse the tree (if TRUE is returned, traversal is stopped)
 */
int clean_entry(gpointer key, struct conn_struct *cur_conn, gpointer trash)
{
	/*! remove the singly linked list
	 */
	g_slist_free(cur_conn->BUFFER);
	char *log = malloc(128);
	sprintf(log,"Singly linked list freed - tuple = %s\n",(char*)key);
	L(NULL,log,2,cur_conn->id);

	return FALSE;
}


/*! term_signal_handler
 *
 \brief called when the program receive a signal that should close the program, free memory and delete lock file
 *
 \param[in] signal_nb: number of the signal
 \param[in] siginfo: informations regarding to the signal
 \param[in] context: NULL
 */

int term_signal_handler(int signal_nb, siginfo_t * siginfo, void *context)
{
	L("term_signal_handler():\t SIGNAL RECEIVED... Halting engine\n",NULL, 1, 2);
	running = NOK;
	g_usleep(999999);

	/*! close pcap output files and context
	 */
///	close_pcap_context();

///	L(31,"TERM_SIGNAL_HANDLER",NULL, 2)

	/*! delete lock file
	 */
	unlink("LOCK_REDIRECTOR");

///	L(8,"TERM_SIGNAL_HANDLER",NULL, 2);

	/*! kill the queue (doesn't work... should fix it)
	 *
	die();
	syslog(LOG_ERR | LOG_USER,"%s","Netfilter Queue destroyed");
	 */

	/*! clean the memory
	 * traverse the B-Tree to remove the singly linked lists and them destroy the B-Tree
	 */
///	g_tree_traverse(conn_tree,(GHRFunc) clean_entry, G_IN_ORDER, NULL );
///	g_tree_destroy(conn_tree);

///	L(28,"TERM_SIGNAL_HANDLER",NULL, 2);


	/*! auto-kill
	 */
///	L(2,"MAIN",NULL, 2);

	/*! sleep for the logs to be committed
	 */
///	if(qh)
///		nfq_destroy_queue(qh);
///	nfq_close(h);
///	nfq_unbind_pf(h, AF_INET);

///	L(14,"TERM_SIGNAL_HANDLER",NULL, 2);
	g_usleep(999999);
	/*! kill myself
	 */
	L("term_signal_handler():\t Stopping complete\n",NULL,1,2);
	exit(signal_nb);
}


/*! call the packet cleaner */
void switch_clean()
{
	clean();
}

/*! call the log engine */
void switch_log()
{
	write_log();
}

/*! Config_parse function, read the configuration from a config file and parse it into a hash table */
int config_parse (char *config_file_name)
{
	FILE *rt;
	char confbuf[CONF_MAX_LINE];

	/*! open config file defined by the "-c" argument
	 */
	if (NULL == (fd = fopen(config_file_name, "r")))
	{
		L("config_parse(): Can't open configuration file",NULL,1,3);

		return -1;
	}

	/*! process each line */
	while (fgets (confbuf, CONF_MAX_LINE, fd))
	{
		/*! if a "#" is found at the beginning of the line, line is a comment */
		if ( NULL != strchr("#",confbuf[0]) || NULL != strchr("\n",confbuf[0]) )
		{
			/// Then, go to next line
		}
		else {
			/*! create a glib table to store the line */
			gchar **line;

			/*! split the line in the table using the pattern ' = ' as a separator */
			line = g_strsplit (confbuf, " = ",0);

			/*! convert values from glib pointer to char * */
			char *key, *value;
			key = g_strdup(line[0]);
			value = g_strdup(line[1]);

			/*! delete '\n' at the end of the line */
			value[strlen(value)-1]='\0';

			/*! add values to config hash table */
			g_hash_table_insert (config, key, value);

			/*! log config parameters */
			char *logbuf = malloc(128);
			sprintf(logbuf,"config_parse(): '%s' = '%s'\n",key,value);
			L(NULL,logbuf,3,3);

			/*! free the memory */
			g_strfreev(line);

		}
	}

	/*! MUST NOT exit before the end of the configuration file */
	if (!feof (fd))
	{
///		L(5,"CONFIG_PARSE",NULL,3);

		g_hash_table_destroy(config);
		config = NULL;
		return -1;
	}

	/*! close config file
	 */
	fclose(fd);


	/*! feed the redirection table with the configuration file */
	if( NULL == g_hash_table_lookup(config,"redirect_table"))
	{
///		L(6,"CONFIG_PARSE","redirect_table",3);

		g_hash_table_destroy(config);
		return -1;
	}
	else {
		/*! open the file
		 */
		if (NULL == (rt = fopen(g_hash_table_lookup(config,"redirect_table"), "r")))
		{
///			L(3,"CONFIG_PARSE",g_hash_table_lookup(config,"redirect_table"), 3);

			return -1;
		}
		/*! process each line */
		while (fgets (confbuf, CONF_MAX_LINE, rt))
		{
			confbuf[strlen(confbuf)-1]=0;
			/*! if a "#" is found at the beginning of the line, line is a comment */
			if ( (0 != strchr("#",confbuf[0])) || (0 != strchr("\n",confbuf[0])) )
				continue;
			///g_print("\tconfig_parse(): '%s'\n",confbuf);

			unsigned lih_[5],hih_[5];
			unsigned *lih_p, *hih_p;
			char *lih = malloc(24);
			char *hih = malloc(24);
			char expr[1024];
			int valid = 1;

			if(sscanf(confbuf,"%i.%i.%i.%i:%i -> %i.%i.%i.%i:%i : %s",lih_, lih_+1, lih_+2, lih_+3, lih_+4,hih_+0, hih_+1, hih_+2, hih_+3, hih_+4 ,expr) != 11)
			{
				///continue;
				valid = 0;
			}

			if(sscanf(confbuf,"%[0-9.:] -> %[0-9.:] : %s",lih,hih,expr) != 3)
			{
				///continue;
				valid = 0;
			}

			if (valid > 0) {

				lih_p = malloc(sizeof(unsigned));
				hih_p = malloc(sizeof(unsigned));

				*lih_p = (lih_[0]<<24) + (lih_[1]<<16) + (lih_[2]<<8) + lih_[3];
				*hih_p = (hih_[0]<<24) + (hih_[1]<<16) + (hih_[2]<<8) + hih_[3];

				if(g_hash_table_lookup(low_honeypot_addr, lih_p) == NULL)
				{
					g_hash_table_insert(low_honeypot_addr, lih_p, lih_p);
				}
				else
					free(lih_p);
	
				if(g_hash_table_lookup(high_honeypot_addr, hih_p) == NULL)
				{
					g_hash_table_insert(high_honeypot_addr, hih_p, hih_p);
				}
				else
					free(hih_p);

				/*! add values to config hash table */
				g_hash_table_insert (low_redirection_table, lih, hih);

				/*! process the equation to create the boolean tree
				 * and store the return tree root in the DE_rules hash table
				 */
				g_hash_table_insert(DE_rules, lih, DE_create_tree(expr));
			}

			if (valid > 0) {
				/*! log config parameters */
				//char *logbuf = malloc(128);
				//sprintf(logbuf,"config_parse(): | %s\n",confbuf);
				//L(NULL,logbuf,3,3);
				g_print("\tconfig_parse(): '%s' (correct)\n",confbuf);
			} else {
				g_print("\tconfig_parse(): '%s' (syntax incorrect!)\n",confbuf);
			}


		}

		/*! MUST NOT exit before the end of the file */
		if (!feof (rt))
		{
///			L(5,"CONFIG_PARSE",NULL,3);

			g_hash_table_destroy(low_redirection_table);
			g_hash_table_destroy(config);
			config = NULL;
			low_redirection_table = NULL;
			return -1;
		}
		fclose(rt);
	}

	return 0;
}



//! Daemonize function, separate the program from the current context
/*!
 */
int daemonize ()
{
	int pid, i;

	/*! Fork to become independent from the father process*/
	pid = fork ();
	if (pid < 0)
	{
		g_print("DAEMON: Error while daemonizing processus... \n");
		return -1;
	}
	if (pid > 0)
	{
		#ifdef DEBUG
		g_print("DAEMON: Exit father's context...\n");
		#endif
		exit(0);
	}

	/*! create a new session */
	setsid();

	/*! Fork to became independent from the terminal process */
	pid = fork ();
	if (pid < 0)
	{
		g_print("DAEMON: Error while daemonizing processus... \n");
		return -1;
	}
	if (pid > 0)
	{
		#ifdef DEBUG
		g_print("DAEMON: Exit terminal's context...\n");
		#endif
		exit(0);
	}

	/*! update defaut mask for files privileges */
	umask (022);

	/*! change execution directory, get path from config hash table */
	if (0 != chdir(g_hash_table_lookup(config,"log_directory")))
	{
		g_print("DAEMON: Unable to move to log directory -> %s\n",(char *) g_hash_table_lookup(config,"log_directory"));
		return -1;
	}


	/*! close files descriptors */
	for (i = getdtablesize(); i>=0; i--)
		close (i);

	/*! Assuming i==0?
	 */

	/*! re-open descriptors 0 */
	if ( NULL != strstr(g_hash_table_lookup(config,"output"),"3") )
	{
		/*! output mode 3: log in a file
		 */
		i = open("honeybrid.log", O_RDWR | O_CREAT, 0640);
		if (i < 0) {
			syslog(LOG_ERR | LOG_USER,"%s","DAEMON: Unable to open log file: honeybrid.log");
			return -1;
		}
		/*
		if ((i = open("honeybrid_redirector_output.csv", O_RDWR | O_CREAT, 0640))) {
			syslog(LOG_USER,"%s","DAEMON: program started, logging to honeybrid_redirector_output.csv");
		}
		else {
			syslog(LOG_ERR | LOG_USER,"%s","DAEMON: Unable to open log file: honeybrid_redirector_output.csv");
			return -1;
		}
		*/
	}
	else {
		/*! otherwise, log in /dev/null
		 */
		i = open("/dev/null", O_RDWR);
	}
	/*! duplicate descriptor 0 to descriptor 1 & 2 ((standard I/O) */
	dup (i);
	dup (i);

	/*! change execution directory, get path from config hash table */
	if (0 != chdir(g_hash_table_lookup(config,"exec_directory")))
	{
		g_print("DAEMON: Unable to move to exec directory -> %s\n",(char *) g_hash_table_lookup(config,"exec_directory"));
		return -1;
	}

	/*! test if a lock file already exist */
	if (NULL != (fd = fopen ((char *) "honeybrid.pid",(char *) "r")))
	{
		g_print("DAEMON: PID file already exists... process still running?\n");
		return -1;
	}
	else
	{	/*! lock does not exist, create it */
		if (NULL == (fd = fopen ("honeybrid.pid", "w+")))
		{
			g_print("DAEMON: Unable to create PID file\n");
			return -1;
		}

		/*! write pid in pid file */
		pid = getpid();
	        fprintf (fd, "%d\n", pid);
	        fclose (fd);
	}

	/*! exit with 0, it's a success */
	return 0;
}

int init_variables()
{
	/*! create the hash table to store the config */
	if (NULL == (config = g_hash_table_new(g_str_hash, g_str_equal)))
	{
		g_print("MAIN: Error while creating config hash table...EXIT\n");
		return -1;
	}

	/*! create the hash table for the log engine */
	if (NULL == (log_table = g_hash_table_new(g_str_hash, g_str_equal)))
	{
		g_print("MAIN: Error while creating log_table hash table...EXIT\n");
		return -1;
	}

	/*! create the hash table for the redirection table */
	if (NULL == (low_redirection_table = g_hash_table_new(g_str_hash, g_str_equal)))
	{
		g_print("MAIN: Error while creating redirection_table hash table...EXIT\n");
		return -1;
	}

	/*! create the hash table for the LIH list */
	if (NULL == (low_honeypot_addr = g_hash_table_new(g_int_hash, g_int_equal)))
	{
		g_print("MAIN: Error while creating low_honeypot_addr hash table...EXIT\n");
		return -1;
	}

	/*! create the hash table for the HIH list */
	if (NULL == (high_honeypot_addr = g_hash_table_new(g_int_hash, g_int_equal)))
	{
		g_print("MAIN: Error while creating high_honeypot_addr hash table...EXIT\n");
		return -1;
	}

	/*! create the hash table to store the pointers to the pools of threads
	 */
	if (NULL == (DE_mod = g_hash_table_new(g_str_hash, g_str_equal)))
	{
		g_print("\t|DE_parse_rules: Error while creating DE_mod hash table...EXIT\n");
		return NOK;
	}
	/*! create the hash table to store the pointers to the boolean execution trees
	 */
	if (NULL == (DE_rules = g_hash_table_new(g_str_hash, g_str_equal)))
	{
		g_print("\t|DE_parse_rules: Error while creating DE_mod hash table...EXIT\n");
		return NOK;
	}


	/*! init the log singly linked list
	 */
	log_list = NULL;

	/*! init the connection id counter
	 */
	c_id = 10;

	/*! init DE_queue
	 */
	DE_queue = NULL;

	/*! Enable data processing
	 */
	running = OK;

	/*! init the security locks
	 */
	g_static_rw_lock_init( &rwlock );
	g_static_rw_lock_init( &loglock );
	g_static_rw_lock_init( &DE_queue_lock );

	/*! g_tree_new_full - create the main B-Tree to store meta informations of active connections
	 *
	\param[in] GCompareDataFunc:  function to compare 2 entries, we use strcmp
	\param[in] GDestroyNotify:  function called to destroy a key
	\param[in] GDestroyNotify:  function called to destroy a value
	\return  a new GTree.
	 */
	if (NULL == (conn_tree =
		   g_tree_new_full((GCompareDataFunc)strcmp,NULL,(GDestroyNotify)g_free,(GDestroyNotify)g_free))
	   )
	{
		g_print("MAIN: Error while creating conn_tree...EXIT\n");
		return -1;
	}
	return 0;
}

/*! process_pkt
 *
 \brief Function called for each received packet, this is the core of the redirection engine
 *
 \param[in] tb a Netfilter Queue structure that contain both the packet and the metadatas
 *
 \return statement = 1 if the packet should be accepted or 0 if the packet has to be dropped. Default is to drop.
 */
static u_int32_t process_pkt(struct nfq_data *tb)
{
	struct conn_struct invalid_connection_data;
	invalid_connection_data.state = INVALID;
	invalid_connection_data.id = 4;
	struct conn_struct * current_connection_data = &invalid_connection_data;
	struct pkt_struct * current_packet_data = (struct pkt_struct *) malloc( sizeof(struct pkt_struct) );
	int statement = 0;
	char *nf_packet;
	struct in_addr in;
	/*! extract ip header from packet payload
	 */
	if(nfq_get_payload(tb, &nf_packet) < 0)
	{
		/*! drop the packet if we cannot extract the payload
		 */
		return statement = 0;
	}

	in.s_addr=((struct iphdr*)nf_packet)->saddr;
	char *log = malloc(128);
	sprintf(log,"process_pkt():\tNew packet received from %s\n",inet_ntoa(in));
	L(NULL, log, 3,current_connection_data->id);
	/*! Start by creating a tuple for this packet, and extract addresses/ports to generate the key
	 */

	/*! check if protocol is invalid (not TCP or UDP)
	*/
	if ( (((struct iphdr*)nf_packet)->protocol != 6) && (((struct iphdr*)nf_packet)->protocol != 17) )
	{
		/*! Then drop the packet
		 */
		return statement = 0;
	}
	
	/*! Initialize the packet structure (into current_packet_data) and find the origin of the packet
	 */
	if(init_packet_struct( nf_packet, current_packet_data) == NOK)
		return statement = 0;
	/*! Initialize the connection structure (into current_connection_data) and get the state of the connection
	 */
	get_current_struct(current_packet_data , &current_connection_data );

///	g_print("\tprocess_pkt(): Origin: %i, State: %i, Data: %i\n",current_packet_data->origin,current_connection_data->state, current_packet_data->data);//toto

	/*! Check that there was no problem getting the current connection structure
	 *  and make sure the STATE is valid
	 */
	if (((current_connection_data->state < INIT)&&(current_packet_data->origin == EXT))||(current_connection_data->state < INVALID)) {	///INIT == 1, INVALID == 0 and NOK == -1
		/*! We drop the packet if there was a problem
		 */
		///reuse log
		log = malloc(128);
		sprintf(log,"process_pkt():\tPacket not from a valid connection %s\n",inet_ntoa(in));
		L(NULL, log, 2,current_connection_data->id);
#ifdef RST_EXT
		if(current_packet_data->packet.ip->protocol==0x06)
			reply_reset( current_packet_data->packet );
#endif
		free_packet_struct(current_packet_data);
///		free(current_packet_data->packet);
///		free(current_packet_data);
		return statement = 0;
	}

	/*! Switch according to the origin of the packet
	 */
	switch( current_packet_data->origin )
	{
		/*! Packet is from the low interaction honeypot
		 */
		case LIH:
			/*! Then we switch according to the state of the connection
			 */
			switch( current_connection_data->state )
			{
				case INIT:
					/*! store packet in memory
                                        */
					if(current_packet_data->packet.ip->protocol == 0x06)
					{
						if(current_packet_data->packet.tcp->syn!=0)
							current_connection_data->hih.lih_syn_seq = ntohl(current_packet_data->packet.tcp->seq);
					}
                                        store_packet(current_connection_data, current_packet_data);

					/*! update statement to 1 (accept)
					 */
					statement = 1;
					break;
				case DECISION:
					/*! store packet in memory
                                        */
                                        store_packet(current_connection_data, current_packet_data);
					DE_push_pkt(current_packet_data);

                                        break;		
				default:
					/*! reset the origin
					*/
					log = malloc(128);
					sprintf(log,"process_pkt():\tPacket from LIH at wrong state => reset %s\n",inet_ntoa(in));
					L(NULL, log, 2,current_connection_data->id);
					if(current_packet_data->packet.ip->protocol==0x06)
						reply_reset( current_packet_data->packet );
					free_packet_struct(current_packet_data);
///					free(current_packet_data->packet);
///					free(current_packet_data);
					break;
			}
			break;

		/*! Packet is from the high interaction honeypot
		 */
		case HIH:
			/*! Then we switch according to the state of the connection
			 */
			switch( current_connection_data->state )
			{
				case REPLAY:
					/*! push the packet to the synchronization list in conn_struct
                                        */
					if(current_packet_data->packet.ip->protocol == 0x06)
					{
						if(current_packet_data->packet.tcp->syn == 1)
						{
							current_connection_data->hih.delta = ~ntohl(current_packet_data->packet.tcp->seq) + 1 + current_connection_data->hih.lih_syn_seq;
						}
					}
                                        replay(current_connection_data, current_packet_data );	
					break;
				case FORWARD:
					/*! forward the packet from the high interaction to the attacker
                                        */
                                        forward(current_packet_data );
					free_packet_struct(current_packet_data);
///					free(current_packet_data->packet);
///					free(current_packet_data);
                                        break;		
				default:
					/*! reset the origin
					*/
					log = malloc(128);
					sprintf(log,"process_pkt():\tPacket from HIH at wrong state => reset %s\n",inet_ntoa(in));
					L(NULL, log, 2,current_connection_data->id);
					if(current_packet_data->packet.ip->protocol==0x06)
						reply_reset( current_packet_data->packet );
					free_packet_struct(current_packet_data);
///					free(current_packet_data->packet);
///					free(current_packet_data);
					break;
			}
			break;

		/*! Packet is from the external attacker (origin == EXT)
		 */
		default:
			/*! Then we switch according to the state of the connection
			 */
			switch( current_connection_data->state )
			{
				case INIT:
					/*! store the packet
                                        */
					store_packet(current_connection_data, current_packet_data);
					
					/*! Test if the packet has data
					 */
					if (current_packet_data->data > 0) {
						/*! Packet has data so we lock and then update the state of the connection
						 */
///						g_static_rw_lock_writer_lock (&current_connection_data->lock);

						current_connection_data->state = DECISION;

///						g_static_rw_lock_writer_unlock (&current_connection_data->lock);

						/*! Then we submit the packet to the Decision Engine
						 */
						DE_push_pkt(current_packet_data);

					} else {
						/*! Packet has no data so we accept it
						 */

						statement = 1;
					}

					break;
				case DECISION:
					store_packet(current_connection_data, current_packet_data);
					DE_push_pkt(current_packet_data);
					break;
				case FORWARD:
					/*! forward the packet from the high interaction to the attacker
					 */
					forward(current_packet_data );
					free_packet_struct(current_packet_data);
///					free(current_packet_data->packet);
///					free(current_packet_data);

					break;		

				default:
					/*! we store the packet for any other state
					 */
					store_packet(current_connection_data, current_packet_data);
					break;
			}
			break;
	}

	/*! reinit keys */

	return statement;
}


/*! q_cb
 *
 \brief Callback function launched by the netfilter queue handler each time a packet is received
 *
 */
static int q_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	/*! get packet id
	 */
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	int id = ntohl(ph->packet_id);

	/*! launch process function
	 */
	u_int32_t statement = process_pkt(nfa);

	/*! ACCEPT the packet if the statement is 1
	 */
	if(statement == 1)
	{
///		L(40,"Q_CB",NULL,1);

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
		\return 0 on success, non-zore on failure
		 */
		return nfq_set_verdict_mark(qh, id, NF_ACCEPT, htonl(0), 0, NULL);
	}
	/*! DROP the packet if the statement is 0 (or something else than 1)
	 */
	else
	{
///		L(41,"Q_CB",NULL,1);

		return nfq_set_verdict_mark(qh, id, NF_DROP, htonl(1), 0, NULL);
	}

}

/*! install_sig_handlers
 \brief installs signal handlers
 \return 0 if exit with success, anything else if not
 */
int install_sig_handlers()
{
	
	/*! Install terminating signal handler:
	*/
	struct sigaction sa_term;
	memset(&sa_term, 0, sizeof sa_term);

	sa_term.sa_sigaction = (void *)term_signal_handler;
	sa_term.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigfillset(&sa_term.sa_mask);

	/*! SIGHUP*/
	if (sigaction(SIGHUP, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGHUP",NULL, 1, 2);
		return NOK;
	}

	/*! SIGINT*/
	if (sigaction(SIGINT, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGINT",NULL, 1, 2);
		return NOK;
	}

	/*! SIGQUIT*/
	if (sigaction(SIGQUIT, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGQUIT",NULL, 1, 2);
		return NOK;
	}

	/*! SIGILL*/
	if (sigaction(SIGILL, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGILL",NULL, 1, 2);
		return NOK;
	}

	/*! SIGSEGV*/
	if (sigaction(SIGSEGV, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGSEGV",NULL, 1, 2);
		return NOK;
	}

	/*! SIGTERM*/
	if (sigaction(SIGTERM, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGTERM",NULL, 1, 2);
		return NOK;
	}
	
	/*! SIGBUS*/
	if (sigaction(SIGBUS, &sa_term, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGBUS",NULL, 1, 2);
		return NOK;
	}

	/*! ignore signals:
	 */
	struct sigaction sa_ignore;
	memset(&sa_ignore, 0, sizeof sa_ignore);
	sa_ignore.sa_handler = SIG_IGN;
	sigfillset(&sa_ignore.sa_mask);
	
	/*! SIGABRT*/
	if (sigaction(SIGABRT, &sa_ignore, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGABRT",NULL, 1, 2);
		return NOK;
	}

	/*! SIGALRM*/
	if (sigaction(SIGALRM, &sa_ignore, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGALRM",NULL, 1, 2);
		return NOK;
	}

	/*! SIGUSR1*/
	if (sigaction(SIGUSR1, &sa_ignore, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGUSR1",NULL, 1, 2);
		return NOK;
	}

	/*! SIGUSR2*/
	if (sigaction(SIGUSR2, &sa_ignore, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGUSR2",NULL, 1, 2);
		return NOK;
	}

	/*! SIGPOLL*/
	if (sigaction(SIGPOLL, &sa_ignore, NULL) != 0)
	{
		L("install_sig_handlers():\tFailed to install sighandler for SIGPOLL",NULL, 1, 2);
		return NOK;
	}

	return OK;
}

/*! main
 \brief process arguments, daemonize, init variables, create QUEUE handler and process each packet
 \param[in] argc, number of arguments
 \param[in] argv, table with arguments
 *
 \return 0 if exit with success, anything else if not
 */
int main(int argc, char *argv[])
{
	int argument;
	char *config_file_name = "";
	GThread *thread_clean;
	GThread *thread_log;

	/*! init glib thread system
	*/
	if (!g_thread_supported ()) g_thread_init (NULL);

	if( argc < 2)
	{
		usage(argv);
		return -1;
	}

	
	if(install_sig_handlers() == NOK)
		return NOK;


	/*! process arguments
	 */
	while ( -1 != (argument = getopt (argc, argv, "sc:x:")))
	{
		switch (argument)
		{
			case 'c' :

				config_file_name = optarg;
				g_print("Start engine with config file: %s\n",config_file_name);
				/*! break to continu to the main program */
				break;


			case 'x' :

				/*! Send a SHUTDOWN request to honeybrid */
				g_print( "Trying to shutdown honeybrid at pid %s\n",optarg);

				/*! convert argument to int */
				int pid = atoi(optarg);

				/*! processus exist ??? */
				if (-1 == kill(pid, 0))
					g_print( "ERROR: Process does not exist\n");

				else
				{
					g_print("Halting engine (remove files, free memory...)\n");

					/*! send signal USR1 to PID */
					int sig=10;

					kill(pid, sig);

					return 0;
				}

				/*! return to stop the execution */
				return -1;
				break;


			case 's' :

				g_print("Status informations not available\n");
				return -1;
				break;


			case '?' :
			default :
				usage(argv);
				return 0;
		}
	}

	/*! initialization
	 */
	if (0 != init_variables() )
		return -1;

	/*! process the configuration files
	 */
	if (0 != config_parse(config_file_name))
		return -1;

	#ifdef DEBUG
	g_print("main(): Configuration file %s parsed\n", config_file_name);
	#endif

	/*! daemonizing method
	 *
	 * if output mode is "2", do not daemonize
	 */
	if ( NULL == strstr(g_hash_table_lookup(config,"output"),"2") )
	{
		/*! separate program from the current context */
		if (0 != daemonize() )
		{
			L("main():\tUnable to separate from the current context",NULL, 1, 1);
			return -1;
		}
	}

	/*! store the pid of the main program */
	mainpid = getpid();

	/*! create a thread for the log engine */
	if( ( thread_log = g_thread_create_full ((void *)switch_log, NULL, 0, FALSE, TRUE,G_THREAD_PRIORITY_LOW, NULL)) == NULL)
	{
		g_print("main():\tError while starting the log engine... EXIT !\n");
		return -1;
	}
	else
		L("main():\tLog engine started\n",NULL,2,1);
///	pcap_record = atoi((char *) g_hash_table_lookup(config,"record"));//toto

	/*! create a thread for the management, cleaning stuffs and so on
	 */
	if( ( thread_clean = g_thread_create_full ((void *)switch_clean, NULL, 0, FALSE, TRUE,G_THREAD_PRIORITY_LOW, NULL)) == NULL)
	{
		L("main():\tUnable to start the Cleaning Thread\n",NULL,1,1);
		return -1;
	}
	else
		L("main():\tCleaning Thread started\n",NULL,2,1);

	/*! init the Decision Engine thread */
	if((thread_log = g_thread_create_full((void *)DE_submit_packet,NULL,0,FALSE,TRUE,0,NULL)) == NULL)
	{
		L("main():\tError while starting the decision engine...\n",NULL,2,1);
		/* ROBIN DEBUG	g_print("main(): Error while starting the log engine... EXIT !\n");	*/
		return -1;
	}
	else
	{
		L("main():\tDecision engine started\n",NULL,2,1);
		/* ROBIN DEBUG  g_print("main(): Decision Engine started\n");	*/
	}

	/*! initiate modules */
	mod_table_init();


	/*! create the two raw sockets for UDP/IP and TCP/IP
	*/
	create_raw_sockets();

	if(tcp_rsd == 0 || udp_rsd == 0)
	{
		L("main():\tFailed to create the RAW sockets\n",NULL,1,1);
		die();
	}

	/*! ********************************************
	 * Create the Netfilter Queue to hook the packets
	 */

	/*! nfq_open
	 \brief Initialise Netfilter Queue context
	 \return pointer to a new queue handle or NULL on failure
	 */
	h = nfq_open();

	/*! control the creation, if it didn't work: exit
	 */
	if (!h) die();

	if (nfq_unbind_pf(h, AF_INET) < 0) {

		L("main():\terror during nfq_unbind_pf()\n",NULL,1,1);

//		die();
//		return -1;
	}

	/*! nfq_bind_pf
	 \brief bind the given queue connection handle to process packets belonging to the given protocol family (ie. PF_INET, PF_INET6, AF_INET, ...)
	 \param[in] h netfilter queue connection handle obtained via call to nfq_open
	 \param[in] AF_INET protocol family
	 */
	int res;
	if ( (res = nfq_bind_pf(h, AF_INET)) < 0) {

		L("main():\terror during nfq_bind_pf()\n",NULL,1,1);

///		die();
		return res;
	}

	/*! nfq_create_queue
	 \brief creates a new queue handle and returns it. The new queue is identified by <num> and the callback specified by <q_cb> will be callled for each enqueued packet. The <data> argument will be passed unchanged to the callback.
	 \param[in] h netfilter queue connection handle obtained via call to nfq_open
	 \param[in] num the number of the queue to bind to
	 \param[in] q_cb cqllbqck function to cqll for each queued packet
	 \param[in] data custom data to pass to the callback function
	 *
	 \return a new queue handle or NULL on failure
	 */
	qh = nfq_create_queue(h,  0, &q_cb, NULL);
	if (!qh) die();

	/*! nfq_set_mode
	 \brief Set the amount of data to be copied to userspace for each packet queued to the given queue
	 \param[in] qh netfilter queue handle obtained by call to nfq_create_queue()
	 \param[in] mode: NFQNL_COPY_NONE -> do not copy any data; NFQNL_COPY_META -> copy only metadata; NFQNL_COPY_PACKET -> copy the entire packet
	 \param[in] 0xffff range
	 *
	 \return 0 on success, non-zero on failure
	 */
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
		die();

	/*! nfq_nfnlh
	 \brief Returns the netlink handle associated with the given queue connection handle
	 \param[in] h netfilter queue connection handle obtained via call to nfq_open
	 *
	 \return The netlink handle associated with the given connection handle. If passed an invalid handle, this function will cause a seg fault
	 */
	nh = nfq_nfnlh(h);

	/*! nfnl_fd
	 \brief return a file descriptor that can be used for receiving the queued packets for processing
	 *
	 \return a file descriptor or -1 on failure
	 */
	fd = (void *)nfnl_fd(nh);

	
	L("main():\tStarting complete, listening to NF_QUEUE\n",NULL,2,1);

	/*! ***********************************************
	 *  process incoming packets and call q_cb for each
	 */
	while (	(received = recv((int)fd, (char *)buf, sizeof(buf), 0)) >= 0 && running == OK)
		/*! process incoming packet */
		nfq_handle_packet(h, (char *)buf, received);

	return 0;
}
