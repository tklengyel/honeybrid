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

/*!	\file tables.c
	\brief Information tables file

	In this file are defined the functions to manage packets.
	TBU

 	\author Julien Vehent, 2007
	\author Thomas Coquelin, 2008
 */

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <time.h>
#include <sys/time.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tables.h"
#include "log.h"
#include "netcode.h"

/*!
 * \brief number of bytes of the buffer in the netfilter callback function
 */
#define CONCALLSIZE 2048

/*! init_pkt
 \brief init the current packet structure with meta-information such as the origin and the number of bytes of data
 \param[in] nf_packet: The raw packet from the queue
 \param[in] pkt: The packet metadata structure for this packet
 \return the origin of the packet
 */
int init_pkt( char *nf_packet, struct pkt_struct *pkt)
{
	/* Init a new structure for the current packet */
	pkt->origin = EXT;
	pkt->DE = 0;
	pkt->packet.ip = malloc( ntohs(((struct iphdr*)nf_packet)->tot_len) ); ///TODO: check if it's correctly freed
	pkt->key = malloc(64);
	pkt->key_src = malloc(32);
	pkt->key_dst = malloc(32);
	pkt->position = 0;
	pkt->size = ntohs(((struct iphdr*)nf_packet)->tot_len);

	if(pkt->size > 1500 || pkt->size <40)
	{
		g_printerr("%s Invalid packet size: dropped\n", H(4));
		return NOK;
	}
	
	/*! Add the packet IP header and payload to the packet structure */
	memcpy( pkt->packet.ip, nf_packet, pkt->size );///THOMAS:Let's save memory!
	if( pkt->packet.ip->ihl < 0x5 || pkt->packet.ip->ihl > 0x08 ) {
		g_printerr("%s Invalid IP header length: dropped\n", H(4));
		return NOK;
	}
	
	pkt->packet.tcp = (struct tcphdr*)(((char *)pkt->packet.ip) + (pkt->packet.ip->ihl<<2));
	pkt->packet.udp = (struct udphdr*)pkt->packet.tcp;
	if( pkt->packet.ip->protocol == 0x06 )
	{
		/*! Process TCP packets */
		if(pkt->packet.tcp->doff < 0x05 || pkt->packet.tcp->doff > 0xFF)
		{
			g_printerr("%s Invalid TCP header length: dropped\n",  H(4));
			return NOK;
		}
		if(pkt->packet.tcp->source == 0 || pkt->packet.tcp->dest == 0)
		{
			g_printerr("%s Invalid TCP ports: dropped\n", H(4));
			return NOK;
		}
		pkt->packet.payload = (char*)pkt->packet.tcp + (pkt->packet.tcp->doff<<2);
		
		/*! key_src is the tuple with the source information
		 * {Source IP}:{Source Port} */
		sprintf( pkt->key_src,"%s:%d",inet_ntoa(*(struct in_addr*)&pkt->packet.ip->saddr),ntohs(pkt->packet.tcp->source) );
		
		/*! key_dst is the one with the destination information
		 * {Dest IP}:{Dest Port} */
		sprintf( pkt->key_dst,"%s:%d",inet_ntoa(*(struct in_addr*)&pkt->packet.ip->daddr),ntohs(pkt->packet.tcp->dest) );
		
		/* The volume of data is the total size of the packet minus the size of the IP and TCP headers */
		pkt->data = ntohs(pkt->packet.ip->tot_len) - (pkt->packet.ip->ihl << 2) - (pkt->packet.tcp->doff << 2);
	} else if( pkt->packet.ip->protocol == 0x11 ) 	/* 0x11 == 17 */
	{
		pkt->packet.payload = (char*)pkt->packet.udp + 8;
		/*! Process UDP packet */
		/*! key_src */
		sprintf( pkt->key_src,"%s:%u",inet_ntoa(*(struct in_addr*)&pkt->packet.ip->saddr),ntohs(pkt->packet.udp->source) );
		/*! key_dst */
		sprintf( pkt->key_dst,"%s:%u",inet_ntoa(*(struct in_addr*)&pkt->packet.ip->daddr),ntohs(pkt->packet.udp->dest) );
		/* The volume of data is the value of udp->ulen minus the size of the UPD header (always 8 bytes) */
		pkt->data = pkt->packet.udp->len - 8; 
	} else 
	{
		/*! Every other packets are ignored */
		g_printerr("%s Invalid protocol: %d, packet dropped\n", H(4), pkt->packet.ip->protocol);
		//L("init_pkt():\tInvalid protocol: dropped\n",NULL,2,4);
		return NOK;
	}

	return OK;
}

/*! free_pkt
 \brief free the current packet structure
 \param[in] pkt: struct pkt_struct to free
 \return OK
 */
int free_pkt( struct pkt_struct *pkt )
{
///	L("free_pkt():\tfreeing NULL !\n",NULL, 3, pkt->conn->id);
	if(pkt == NULL)
		return NOK;
	g_free(pkt->packet.ip);
	g_free(pkt->key);
	g_free(pkt->key_src);
	g_free(pkt->key_dst);
	g_free(pkt);
	return OK;
}

/*! init_conn
 \brief init the current context using the tuples
 \param[in] pkt: struct pkt_struct to work with
 \param[in] conn: struct conn_struct to work with
 \return 0 if success, anything else otherwise
 */
int init_conn(struct pkt_struct *pkt, struct conn_struct **conn)
{
	#ifdef DEBUG
	g_printerr("%s ~~~~ function called ~~~~\n", H(0));
	#endif

	/*! Get current time to update or create the structure
	 */
	GTimeVal t;
	g_get_current_time(&t);
	gint curtime = (t.tv_sec);

	gdouble microtime = 0.0;
	microtime +=  ((gdouble)t.tv_sec);
	microtime += (((gdouble)t.tv_usec)/1000000.0);

	/*! if key->str is null, then we have a seg fault! And it can happen if no LIH was found from a HIH->EXT packet...
	if ( pkt->key == NULL ) {
		g_printerr("%s key is NULL, no valid connection attached\n", H(4));
		return NOK;
	}
	 */
	char *key0 = malloc(64);
        sprintf(key0, "%s:%s", pkt->key_src, pkt->key_dst);
	char *key1 = malloc(64);
        sprintf(key1, "%s:%s", pkt->key_dst, pkt->key_src);

	int update = 0;
	int create = 0;

	if (TRUE == g_tree_lookup_extended(conn_tree, key0, NULL,(gpointer *) conn)) {
		snprintf(pkt->key, 64, "%s", key0);
		pkt->origin = EXT;
		//pkt->origin = HIH; //?
		update = 1;	
	} else if (TRUE == g_tree_lookup_extended(conn_tree, key1, NULL,(gpointer *) conn)) {
		snprintf(pkt->key, 64, "%s", key1);
		pkt->origin = LIH;
		update = 1;	
	} else {
		create = 1;
	}

	free(key0);
	free(key1);

	if (create == 1) {
		#ifdef DEBUG
		g_printerr("%s ~~~~ Creating a new connection structure ~~~~\n", H(0));
		#endif
		/*! The key could not be found, then we make sure that the packet is from an external IP
		 */
		///We now accept packets from HIH or LIH because we can then control them
		///if ( pkt->origin != EXT )
			/*! The source is not external, then we invalidate the state */
		///	return NOK;
		///else if(pkt->packet.ip->protocol == 0x06 && pkt->packet.tcp->syn == 0 )
		if(pkt->packet.ip->protocol == 0x06 && pkt->packet.tcp->syn == 0 ) {
			g_printerr("%s ~~~~ TCP packet without SYN: we drop ~~~~\n", H(0));
			return NOK;
		}

		/*! Try to match a target with the destination of this packet */
		int found = -1;
		int i = 0;
		for (i = 0; i < targets->len; i++) {
			#ifdef DEBUG
			g_printerr("%s ~~~~ ...looking for target %d... ~~~~\n", H(0), i);
			#endif
			if(bpf_filter(
			    ((struct target *)g_ptr_array_index(targets,i))->filter->bf_insns, 
			    (u_char *)pkt->packet.ip, 
			    pkt->size, 
			    pkt->size) != 0) {
				g_printerr("%s Target found!\n", H(0));
				found = i;
				snprintf(pkt->key, 64, "%s:%s", pkt->key_src, pkt->key_dst);
				pkt->origin = EXT;
				break;
			}	
		}

		/*! If not, then it means the packets is originated from a honeypot inside */
		if (found < 0) {
			g_printerr("%s No target found\n", H(0));
			/*! check if the src is in the honeynet */
			snprintf(pkt->key, 64, "%s:%s", pkt->key_dst, pkt->key_src);
			pkt->origin = LIH;

			/*! if not, then this packet is for an unconfigured target, we drop it */
			g_printerr("%s Dropping for now\n", H(0));
			return NOK;
		}

		/*! Update state to be INIT */

		/*! Init new connection structure */
		struct conn_struct *conn_init = (struct conn_struct *) malloc( sizeof(struct conn_struct) );

		/*! fill the structure */
		conn_init->target			= g_ptr_array_index(targets,i);

		conn_init->key				= g_strdup(pkt->key);
		conn_init->key_ext				= g_strdup(pkt->key_src);
		conn_init->key_lih				= g_strdup(pkt->key_dst);
		conn_init->key_hih				= NULL;
		conn_init->protocol				= pkt->packet.ip->protocol;
		conn_init->access_time			= curtime;
		conn_init->state		 		= INIT;
		conn_init->count_data_pkt_from_lih 		= 0;
		conn_init->count_data_pkt_from_intruder 	= 0;
		conn_init->BUFFER				= NULL;
		conn_init->hih.lih_syn_seq			= 0;
		conn_init->hih.delta				= 0;
		conn_init->id				= c_id++;
		conn_init->replay_id				= 0;
		g_static_rw_lock_init( &conn_init->lock );
		int j;
		for (j = INVALID; j<= CONTROL; j++) {
			conn_init->stat_time[j]   = 0.0;
			conn_init->stat_packet[j] = 0;
			conn_init->stat_byte[j]   = 0;	
		}	

		/*! statistics */
		conn_init->start_microtime = microtime;
		conn_init->stat_time[   INIT ] = microtime;
		conn_init->stat_packet[ INIT ] = 1;
		conn_init->stat_byte[   INIT ] = pkt->size;
		conn_init->total_packet = 1;
		conn_init->total_byte   = pkt->size;
		conn_init->replay_problem = 0;
		conn_init->invalid_problem = 0;
		///conn_init->decision_rule = malloc(512);
		conn_init->decision_rule = g_string_new(NULL);

		struct tm *tm;
                struct timeval tv;
                struct timezone tz;
                gettimeofday(&tv, &tz);
                tm=localtime(&tv.tv_sec);
		conn_init->start_timestamp = g_string_new("");
                g_string_printf(conn_init->start_timestamp,"%d-%02d-%02d %02d:%02d:%02d.%.6d", (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec);
		

		/*! insert entry in B-Tree
		 * (set up a lock to protect the writing)
		 */
		g_static_rw_lock_writer_lock (&rwlock);

		g_tree_insert(conn_tree, conn_init->key, conn_init);

		/*! free the lock */
		g_static_rw_lock_writer_unlock (&rwlock);

		g_printerr("%s New entry created in B-Tree for connection %s\n", H(conn_init->id), conn_init->key);

		/*! store new entry in current struct */

		if (TRUE != g_tree_lookup_extended(conn_tree, pkt->key, NULL,(gpointer *) conn))
			return NOK;

	} 

	if (update == 1) {
		#ifdef DEBUG
		g_printerr("%s ~~~~ Updating an existing structure ~~~~\n", H(0));
		#endif

		/*! The key was found in the B-Tree */
		int state = (*conn)->state;

		/*! We store control statistics in the proxy mode */
		if (state == CONTROL) {
			state = PROXY;
		}

		/*! We lock the structure */
		///ROBIN 2009-03-29: deadlock occurred between here and line 676 (setup_redirection())
		//g_static_rw_lock_writer_lock( &(*conn)->lock );
		/*
		#ifdef DEBUG
		g_print("init_conn()\tTrying to unlock conn for connection id %d\n", (*conn)->id);
		#endif
		while (!g_static_rw_lock_writer_trylock( &(*conn)->lock )) {
			g_usleep(1);
			//g_static_rw_lock_writer_unlock( &(*conn)->lock );
		}
		*/
		/*! statistics */
		(*conn)->stat_time[   state ]  = microtime;
		(*conn)->stat_packet[ state ] += 1;
		(*conn)->stat_byte[   state ] += pkt->size;
		(*conn)->total_packet += 1;
		(*conn)->total_byte   += pkt->size;
		/*! We update the current connection access time */
		(*conn)->access_time = curtime;
		if(pkt->origin == EXT)
			(*conn)->count_data_pkt_from_intruder += pkt->packet.tcp->psh;

		/*! We unlock the structure */
		///g_static_rw_lock_writer_unlock( &(*conn)->lock );

	}


	pkt->conn = *conn;

	#ifdef DEBUG
	g_printerr("%s ~~~~ returning ~~~~\n", H(0));
	#endif

	return OK;
}

/*! addr2int
 * \brief Convert an IP address from string to int
 * \param[in] the IP address (string format)
 *
 * \return the IP address (int format)
 */
int addr2int(char *address) {
        gchar **addr;
	int intaddr;

        addr = g_strsplit ( address, ".", 0 );

        intaddr =  atoi(addr[0]) << 24;
        intaddr += atoi(addr[1]) << 16;
        intaddr += atoi(addr[2]) << 8;
        intaddr += atoi(addr[3]);
	g_strfreev(addr);
	return intaddr;
}



/*! test_honeypot_addr
 *
 * \brief compare an IP with a list of honeypot addresses
 * \param[in] the key ip:port of the host we want to test in the list
 * \param[in] the list we want to look into, either Low or High
 *
 * \return 0 if the key is found in the list, anything else if not
 */
int test_honeypot_addr( char *key, int list ) {
	gchar **addr;
	GString *testkey = g_string_new(key);

	/*! We extract the IP from the key */
	addr = g_strsplit( testkey->str, ":", 0);

	/*! small hack to be able to define matching pattern for multiple IP at once
         */
        gchar **byte;
        byte = g_strsplit (addr[0], ".", 0);
        GString *classA, *classB, *classC;
        classA = g_string_new("");
        classB = g_string_new("");
        classC = g_string_new("");
	g_string_printf(classA,"%s.0.0.0",byte[0]);
        g_string_printf(classB,"%s.%s.0.0",byte[0],byte[1]);
        g_string_printf(classC,"%s.%s.%s.0",byte[0],byte[1],byte[2]);

	/*! We convert the IP from char to int */
	int intaddr = addr2int( addr[0] );
	int intaddrA = addr2int( classA->str );
	int intaddrB = addr2int( classB->str );
	int intaddrC = addr2int( classC->str );

	g_strfreev(addr);
	g_strfreev(byte);
	g_string_free(testkey,TRUE);
	
	/*! We test which list we want to search */
	if ( list == LIH && g_hash_table_lookup(low_honeypot_addr, &intaddr) != NULL) 
	/*! if the IP is detected in the list of low honeypot addresses */
		return OK;
	/*! We then test by increasing the size of the network progressively: */
	if ( list == LIH && g_hash_table_lookup(low_honeypot_addr, &intaddrC) != NULL) 
		return OK;
	if ( list == LIH && g_hash_table_lookup(low_honeypot_addr, &intaddrB) != NULL) 
		return OK;
	if ( list == LIH && g_hash_table_lookup(low_honeypot_addr, &intaddrA) != NULL) 
		return OK;

	if( list == HIH && g_hash_table_lookup(high_honeypot_addr, &intaddr) != NULL)
	/*! if the IP is detected in the list of high honeypot addresses */
		return OK;
	return NOK;
}

/*! lookup_honeypot_addr
 *
 * \brief return the low/high interaction honeypot currently associated with the low/high interaction honeypot in argument
 * \param[in] the key of the honeypot, or honeypot+external host, we want to lookup in the redirection table
 * \param[in] the list we want to look into, either Low or High
 *
 * \return The honeypot IP found, NULL if nothing is found
 */
char * lookup_honeypot_addr( gchar *testkey, int list ) {

	g_printerr("%s Looking up %s in list %d (LIH == 1, HIH == 2)\n", H(5), testkey, list);
	
	/*! We test which list we want to search */
	if ( list == LIH ) {
		/*! ROBIN 2009-02-25: small hack to include full network definition */
		gchar **addr;
		addr = g_strsplit( testkey, ":", 0);

		gchar **byte;
	        byte = g_strsplit (testkey, ".", 0);
	        GString *classA, *classB, *classC;
	        classA = g_string_new("");
	        classB = g_string_new("");
	        classC = g_string_new("");
	        g_string_printf(classA,"%s.0.0.0:%s",byte[0],addr[1]);
	        g_string_printf(classB,"%s.%s.0.0:%s",byte[0],byte[1],addr[1]);
	        g_string_printf(classC,"%s.%s.%s.0:%s",byte[0],byte[1],byte[2],addr[1]);

	        /*! get the corresponding hih destination from the low interaction hash table */
	        char *hihdest;
	        hihdest = g_strdup((char *)g_hash_table_lookup(low_redirection_table, testkey));

	        if(!hihdest)
	        	hihdest = g_strdup((char *)g_hash_table_lookup(low_redirection_table, classC->str));
	        if(!hihdest)
	        	hihdest = g_strdup((char *)g_hash_table_lookup(low_redirection_table, classB->str));
	        if(!hihdest)
	        	hihdest = g_strdup((char *)g_hash_table_lookup(low_redirection_table, classA->str));
	        if(!hihdest) {
			g_printerr("%s Tested also %s, %s and %s but nothing matched\n", H(5), classC->str, classB->str, classA->str);
	                return NULL;
		}

		g_printerr("%s Found %s!\n", H(5), hihdest);

	        return hihdest;

	} else {
                /*! get the corresponding lih destination from the high interaction hash table */

		/*! Check first if the high_redirection_table is not null */
		if (high_redirection_table == NULL)
			return NULL;

                char *lihdest;
		lihdest = g_strdup((char *)g_hash_table_lookup(high_redirection_table, testkey));

                if(!lihdest)
                        return NULL;

		g_printerr("%s Found %s!\n", H(5), lihdest);

                return lihdest;
	}
	return NULL;
}

/*! store_pkt function
 \brief Store the current packet as part of the connection to replay it later. If this is the first packet of a communication, init its structure in the main B-Tree.
 *
 \param[in] pkt: struct pkt_struct to work with
 \param[in] conn: struct conn_struct to work with
 *
 \return the position of the packet in the list in case of success, a negative value if storage has failed
 */
int store_pkt(struct conn_struct *conn, struct pkt_struct *pkt)
{
	pkt->position = -1;
	/*! Lock the structure */
	///g_static_rw_lock_writer_lock (&conn->lock);

	/*! Append pkt to the singly-linked list of conn */
        conn->BUFFER = g_slist_append(conn->BUFFER, pkt);

	/*! Get the packet position */
        pkt->position = (g_slist_length(conn->BUFFER) - 1);

	/*! Unlock the structure */
        ///g_static_rw_lock_writer_unlock (&conn->lock);	
	
	g_printerr("%s Packet stored in memory for connection %s\n", H(conn->id), conn->key);

	return OK;
}


/*! expire_conn
 \brief called for each entry in the B-Tree, if a time value is upper to "expiration_delay" (default is 120 sec) and the connection is not marked as redirected, entry is deleted
 \param[in] key, a pointer to the current B-Tree key value
 \param[in] conn, a pointer to the current B-Tree associated value
 \param[in] expiration_delay
 \return FALSE, to continue to traverse the tree (if TRUE is returned, traversal is stopped)
 */
int expire_conn(gpointer key, struct conn_struct *conn, gint *expiration_delay)
{
	GTimeVal t;
	g_get_current_time(&t);
	gint curtime = (t.tv_sec);

	GSList *current;
	struct pkt_struct* tmp;

	int delay = *expiration_delay;

	/*
	#ifdef DEBUG
	g_printerr("%s called with expiration delay: %d\n", H(8), delay);
	#endif
	*/

	if(((curtime - conn->access_time) > delay) || (conn->state < INIT))
	{
		/*! output final statistics about the connection */
		connection_log(conn);

		g_printerr("%s Singly linked list freed - tuple = %s\n", H(conn->id), (char*)key);

		/*! lock the structure, this will never be unlocked */
		g_static_rw_lock_writer_lock (&conn->lock);

		/*! remove the singly linked lists */
		current = conn->BUFFER;
		if (current != NULL) {
			do{
				tmp = (struct pkt_struct*) g_slist_nth_data ( current, 0 );
				free_pkt(tmp);
			}while((current = g_slist_next(current)) != NULL);
		}

		g_slist_free(conn->BUFFER);
		g_free(conn->key_ext);
		g_free(conn->key_lih);
		g_free(conn->key_hih);
		///free(conn->decision_rule);
		g_string_free(conn->decision_rule, TRUE);

		/*! list the entry for later removal */
		g_ptr_array_add(entrytoclean, key);
	}
	return FALSE;
}

/*! free_conn
 \brief called for each entry in the pointer array, each entry is a key that is deleted from the B-Tree
 \param[in] key, a pointer to the current B-Tree key value stored in the pointer table
 \param[in] trash, user data, unused
 */
void free_conn(gpointer key, gpointer trash)
{
	g_printerr("%s entry removed - tuple = %s\n", H(8), (char*)key);

	g_static_rw_lock_writer_lock (&rwlock);

	if (TRUE != g_tree_remove(conn_tree,key)) {
		g_printerr("%s Error while removing tuple %s\n", H(8), (char*)key);
		free(key);
	}
	g_static_rw_lock_writer_unlock (&rwlock);
}

/*! clean
 \brief watchman for the b_tree, wake up every 5 minutes and check every entries
 */
void clean()
{

	char *expiration_delay = g_hash_table_lookup(config,"expiration_delay");
	if( expiration_delay == NULL ) {
		expiration_delay = "120";
	}
	int delay = atoi(expiration_delay);

	/*! DEBUG
	char *log = malloc(192);
        sprintf(log,"clean():\texpiration delay set to %d seconds\n", delay);
        L(NULL,log,3,8);
	*/

	while ( threading == OK )
	{
		/*! wake up every second */
		g_usleep(999999);
		/*
		#ifdef DEBUG
		g_printerr("%s cleaning\n", H(8));
		#endif
		*/

		/*! init the table*/
		entrytoclean = g_ptr_array_new();

		/*! call the clean function for each value, delete the value if TRUE is returned */
		g_tree_traverse( conn_tree,(GHRFunc) expire_conn, G_IN_ORDER, &delay );

		/*! remove each key listed from the btree */
		g_ptr_array_foreach(entrytoclean,(GFunc) free_conn, NULL);

		/*! free the array */
		g_ptr_array_free(entrytoclean, TRUE);
	}
}





/*! setup_redirection
 \brief called for each connection being redirected to setup and start the redirection process
 \param[in] conn: redirected connection metadata
 \return OK when done, NOK in case of failure
 */
int setup_redirection(struct conn_struct *conn)
{
	g_printerr("%s [** Starting... **]\n", H(conn->id));

	char* hihaddr = lookup_honeypot_addr( conn->key_lih, LIH );

	if ( hihaddr != NULL ) {
		/*! If a high interaction was found, we then check that it's not currently used by the same external host IP and Port */
		GString *key_hih_ext = g_string_new( "" );
		g_string_printf( key_hih_ext, "%s:%s", hihaddr, conn->key_ext );

		if ( lookup_honeypot_addr( key_hih_ext->str, HIH ) == NULL )
		{
			/*! No concurrent redirection detected so we can move forward in this one */

			/*! We start by registering the HIH:EXT->LIH dynamic relation into high_redirection_table
			 * to prevent any similar redirection from being started */

			/*! We need first to initialize the high_redirection_table */
			if ( high_redirection_table == NULL )
			{
				high_redirection_table = g_hash_table_new (g_str_hash, g_str_equal);
			}

			g_hash_table_insert (high_redirection_table, key_hih_ext->str, conn->key_lih );

			g_printerr("%s [** high_redirection_table updated **]\n", H(conn->id));

			GTimeVal t;
		        g_get_current_time(&t);
		        gdouble microtime = 0.0;
		        microtime +=  ((gdouble)t.tv_sec);
		        microtime += (((gdouble)t.tv_usec)/1000000.0);

			gchar **tmp_ = g_strsplit( hihaddr, ":", 0);

			int tmp_port;
			sscanf(tmp_[1],"%i",&tmp_port);

			/*! We update the connection structure with the high interaction honeypot found */
			///ROBIN 2009-03-29: deadlock occurred between here and line 312 (init_conn())
			///g_static_rw_lock_writer_lock (&conn->lock);
			/*
			#ifdef DEBUG
			g_print("setup_redirection()\tTrying to unlock conn for connection id %d\n", conn->id);
			#endif
			while (!g_static_rw_lock_writer_trylock( &conn->lock )) {
				g_usleep(1);
				//g_static_rw_lock_writer_unlock( &conn->lock );
			}
			*/
			conn->key_hih = hihaddr;
			conn->hih.addr = htonl(addr2int( *tmp_ ));
			conn->hih.lih_addr = htonl(addr2int( conn->key_lih ));
			conn->hih.port = htons( (short)tmp_port );
			/*! We then update the status of the connection structure
			 */
			conn->stat_time[ DECISION ] = microtime;
			conn->state = REPLAY;

			///g_static_rw_lock_writer_unlock (&conn->lock);

			g_printerr("%s State updated to REPLAY\n", H(conn->id));

			g_strfreev(tmp_);
			g_string_free(key_hih_ext,0);

			/*! We reset the LIH */
			reset_lih( conn );

			/*! We replay the first packets */
			struct pkt_struct* current;
			current = (struct pkt_struct*) g_slist_nth_data ( conn->BUFFER, conn->replay_id );

			g_printerr("%s [** starting the forwarding loop... **]\n", H(conn->id));
			// Does not correctly replay when MIN_DATA_DECISION is 0...
			while(current->origin == EXT)
			{
				forward(current);
				if(g_slist_next(g_slist_nth( conn->BUFFER, conn->replay_id )) == NULL)
				{
					///g_static_rw_lock_writer_lock (&conn->lock);
					conn->state = FORWARD;
					///g_static_rw_lock_writer_unlock (&conn->lock);
					g_printerr("%s State updated to FORWARD\n", H(conn->id));
					///g_string_free(key_hih_ext, TRUE);	///Seg fault - ROBIN - 2009-04-09
					return OK;
				}
				///g_static_rw_lock_writer_lock (&conn->lock);
				conn->replay_id++;
				///g_static_rw_lock_writer_unlock (&conn->lock);
				current = (struct pkt_struct*) g_slist_nth_data ( conn->BUFFER, conn->replay_id );
			}
			g_printerr("%s [** ...done with the forwarding loop **]\n", H(conn->id));
			g_printerr("%s [** defining expected data **]\n", H(conn->id));
			/*! then define the next expected data */
			define_expected_data(current);
			///g_static_rw_lock_writer_lock (&conn->lock);
			conn->replay_id++;
			///g_static_rw_lock_writer_unlock (&conn->lock);
		} else {
			g_string_free(key_hih_ext, TRUE);
		}
	}
	else
		return NOK;
	return OK;
}


/*! config_lookup
 /brief lookup values from the config hash table. Make sure the required value is present
 */

char * 
config_lookup(char * parameter) {
	if (NULL == g_hash_table_lookup(config, parameter)) {
		errx(1, "Missing configuration parameter '%s'", parameter);
	}
	return (char *)g_hash_table_lookup(config, parameter);
}

