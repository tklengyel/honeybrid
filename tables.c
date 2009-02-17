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

/*! init_packet_struct
 \brief init the current packet structure with meta-information such as the origin and the number of bytes of data
 \param[in] nf_packet: The raw packet from the queue
 \param[in] new_packet_data: The packet metadata structure for this packet
 \return the origin of the packet
 */
int init_packet_struct( char *nf_packet, struct pkt_struct *new_packet_data)
{
	/* Init a new structure for the current packet */
	new_packet_data->origin = EXT;
	new_packet_data->DE = 0;
	new_packet_data->packet.ip = malloc( ntohs(((struct iphdr*)nf_packet)->tot_len) );
	new_packet_data->key = malloc(64);
	new_packet_data->key_src = malloc(32);
	new_packet_data->key_dst = malloc(32);
	new_packet_data->position = 0;
	new_packet_data->size = ntohs(((struct iphdr*)nf_packet)->tot_len);

	if(new_packet_data->size > 1500 || new_packet_data->size <40)
	{
		L("init_packet_struct():\tInvalid packet size: dropped\n",NULL,2,4);
		return NOK;
	}
	
	/*! Add the packet IP header and payload to the packet structure */
	memcpy( new_packet_data->packet.ip, nf_packet, new_packet_data->size );///THOMAS:Let's save memory !
	if( new_packet_data->packet.ip->ihl < 0x5 || new_packet_data->packet.ip->ihl > 0x08 )
	{
		L("init_packet_struct():\tInvalid IP header length: dropped\n",NULL,2,4);
		return NOK;
	}
	
	new_packet_data->packet.tcp = (struct tcphdr*)(((char *)new_packet_data->packet.ip) + (new_packet_data->packet.ip->ihl<<2));
	new_packet_data->packet.udp = (struct udphdr*)new_packet_data->packet.tcp;
	if( new_packet_data->packet.ip->protocol == 0x06 )
	{
		/*! Process TCP packets */
		if(new_packet_data->packet.tcp->doff < 0x05 || new_packet_data->packet.tcp->doff > 0xFF)
		{
			L("init_packet_struct():\tInvalid TCP header length: dropped\n",NULL,2,4);
			return NOK;
		}
		if(new_packet_data->packet.tcp->source == 0 || new_packet_data->packet.tcp->dest == 0)
		{
			L("init_packet_struct():\tInvalid TCP ports: dropped\n",NULL,2,4);
			return NOK;
		}
		new_packet_data->packet.payload = (char*)new_packet_data->packet.tcp + (new_packet_data->packet.tcp->doff<<2);
		
		/*! key_src is the tuple with the source information
		 * {Source IP}:{Source Port} */
		sprintf( new_packet_data->key_src,"%s:%d",inet_ntoa(*(struct in_addr*)&new_packet_data->packet.ip->saddr),ntohs(new_packet_data->packet.tcp->source) );
		
		/*! key_dst is the one with the destination information
		 * {Dest IP}:{Dest Port} */
		sprintf( new_packet_data->key_dst,"%s:%d",inet_ntoa(*(struct in_addr*)&new_packet_data->packet.ip->daddr),ntohs(new_packet_data->packet.tcp->dest) );
		
		/* The volume of data is the total size of the packet minus the size of the IP and TCP headers */
		new_packet_data->data = ntohs(new_packet_data->packet.ip->tot_len) - (new_packet_data->packet.ip->ihl << 2) - (new_packet_data->packet.tcp->doff << 2);
	}
	else if( new_packet_data->packet.ip->protocol == 0x17 )
	{
		new_packet_data->packet.payload = (char*)new_packet_data->packet.udp + 8;
		/*! Process UDP packet */
		/*! key_src */
		sprintf( new_packet_data->key_src,"%s:%u",inet_ntoa(*(struct in_addr*)&new_packet_data->packet.ip->saddr),ntohs(new_packet_data->packet.udp->source) );
		/*! key_dst */
		sprintf( new_packet_data->key_dst,"%s:%u",inet_ntoa(*(struct in_addr*)&new_packet_data->packet.ip->daddr),ntohs(new_packet_data->packet.udp->dest) );
		/* The volume of data is the value of udp->ulen minus the size of the UPD header (always 8 bytes) */
		new_packet_data->data = new_packet_data->packet.udp->len - 8; 
	}
	else
	{
		/*! Every other packets are ignored */
		L("init_packet_struct():\tInvalid protocol: dropped\n",NULL,2,4);
		return NOK;
	}

	/* Use key_src and key_dst to find the origin of the packet */
	if ( test_honeypot_addr( new_packet_data->key_src, LIH ) == OK) 
	{
		/* The source is matching the IP of a low interaction honeypot
		 * We update origin accordingly */
		new_packet_data->origin = LIH;

		/* We also update the key to be key_dst:key_src */
		sprintf( new_packet_data->key, "%s:%s", new_packet_data->key_dst, new_packet_data->key_src );
	}
	else if ( test_honeypot_addr( new_packet_data->key_src, HIH ) == OK )
	{
		/* The source is matching the IP of a high interaction honeypot
		 * We update origin accordingly	 */
		new_packet_data->origin = HIH;

		/* We create a key HIH:EXT to check the high interaction dynamic table of IPs and find the associated low interaction honeypot */
		char *double_key = malloc(64);
		sprintf(double_key, "%s:%s", new_packet_data->key_src, new_packet_data->key_dst );
		char *key_lih = lookup_honeypot_addr( double_key, HIH );

		if ( (key_lih) )
			/* We also update the key to be key_dst:key_lih */
			sprintf( new_packet_data->key, "%s:%s", new_packet_data->key_dst, key_lih);
		else 
			/* if we did not find any LIH, we then invalidate key with the null value */
			new_packet_data->key = NULL;
		free(key_lih);
		free(double_key);
	}
	else
		/* We did not find the IP in the list of low/high interaction honeypot, then the IP is external */
		sprintf( new_packet_data->key, "%s:%s", new_packet_data->key_src, new_packet_data->key_dst );
	return OK;
}

/*! free_packet_struct
 \brief free the current packet structure
 \param[in] pkt: struct pkt_struct to free
 \return OK
 */
int free_packet_struct( struct pkt_struct *pkt )
{
///	L("free_packet_struct():\tfreeing NULL !\n",NULL, 3, pkt->connection_data->id);
	if(pkt == NULL)
		return NOK;
	free(pkt->packet.ip);
	free(pkt->key);
	free(pkt->key_src);
	free(pkt->key_dst);
	free(pkt);
	return OK;
}


/*! get_current_struct
 \brief init the current context using the tuples
 \param[in] current_packet_data: struct pkt_struct to work with
 \param[in] current_connection_data: struct conn_struct to work with
 \return 0 if success, anything else otherwise
 */
int get_current_struct(struct pkt_struct *current_packet_data, struct conn_struct **current_connection_data)
{
	/*! Get current time to update or create the structure
	 */
	GTimeVal t;
	g_get_current_time(&t);
	gint curtime = (t.tv_sec);

	/*! g_tree_lookup_extended - lookup for a key in the B-Tree
	 *
	\param[in] conn_tree:  name of the b-tree
	\param[in] key->str:  key value
	\param[in] NULL:  unused options
	\param[in] (gpointer *) &current_connection_data:  pointer to the value
	 *
	\return TRUE if value exist
	 */
	
	/*! if key->str is null, then we have a seg fault! And it can happen if no LIH was found from a HIH->EXT packet...
	 */
	if ( current_packet_data->key == NULL )
		/*! We return the Invalid state */
		return NOK;

	if (TRUE != g_tree_lookup_extended(conn_tree, current_packet_data->key, NULL,(gpointer *) current_connection_data))
	{
		/*! The key could not be found, then we make sure that the packet is from an external IP
		 */
		if ( current_packet_data->origin != EXT )
			/*! The source is not external, then we invalidate the state */
			return NOK;
		else if(current_packet_data->packet.ip->protocol == 0x06 && current_packet_data->packet.tcp->syn == 0 )
			return NOK;

		/*! Update state to be INIT */

		/*! Init new connection structure */
		struct conn_struct *add_new_data = (struct conn_struct *) malloc( sizeof(struct conn_struct) );

		/*! fill the structure */
		add_new_data->key				= g_strdup(current_packet_data->key);
		add_new_data->key_ext				= g_strdup(current_packet_data->key_src);
		add_new_data->key_lih				= g_strdup(current_packet_data->key_dst);
		add_new_data->key_hih				= NULL;
		add_new_data->protocol				= current_packet_data->packet.ip->protocol;
		add_new_data->access_time			= curtime;
		add_new_data->state		 		= INIT;
		add_new_data->count_data_pkt_from_lih 		= 0;
		add_new_data->count_data_pkt_from_intruder 	= 0;
		add_new_data->BUFFER				= NULL;
		add_new_data->hih.lih_syn_seq			= 0;
		add_new_data->hih.delta				= 0;
		add_new_data->id				= c_id++;
		add_new_data->replay_id				= 0;
		g_static_rw_lock_init( &add_new_data->lock );

		/*! insert entry in B-Tree
		 * (set up a lock to protect the writing)
		 */
		g_static_rw_lock_writer_lock (&rwlock);

		g_tree_insert(conn_tree, add_new_data->key, add_new_data);

		/*! free the lock */
		g_static_rw_lock_writer_unlock (&rwlock);
		char* logbuf = malloc(128);
		sprintf(logbuf,"get_current_struct():\tNew entry created in B-Tree for connection %s\n",add_new_data->key);
		L(NULL,logbuf,2,add_new_data->id);

		/*! store new entry in current struct */

		if (TRUE != g_tree_lookup_extended(conn_tree, current_packet_data->key, NULL,(gpointer *) current_connection_data))
			return NOK;

	} else {
		/*! The key was found in the B-Tree */
		/*! We lock the structure */

		g_static_rw_lock_writer_lock( &(*current_connection_data)->lock );

		/*! We update the current connection access time */
		(*current_connection_data)->access_time = curtime;
		if(current_packet_data->origin == EXT)
			(*current_connection_data)->count_data_pkt_from_intruder += current_packet_data->packet.tcp->psh;
		/*! We unlock the structure */
		g_static_rw_lock_writer_unlock( &(*current_connection_data)->lock );

	}
	current_packet_data->connection_data = *current_connection_data;
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
 * \param[in] the key of the host we want to test in the list
 * \param[in] the list we want to look into, either Low or High
 *
 * \return 0 if the key is found in the list, anything else if not
 */
int test_honeypot_addr( char *key, int list ) {
	gchar **addr;
	GString *testkey = g_string_new(key);

	/*! We extract the IP from the key */
	addr = g_strsplit( testkey->str, ":", 0);

	/*! We convert the IP from char to int */
	int intaddr = addr2int( addr[0] );
	g_strfreev(addr);
	g_string_free(testkey,TRUE);
	
	/*! We test which list we want to search */
	if ( list == LIH && g_hash_table_lookup(low_honeypot_addr, &intaddr) != NULL) 
	/*! if the IP is detected in the list of low honeypot addresses */
		return OK;
	else if( list == HIH && g_hash_table_lookup(high_honeypot_addr, &intaddr) != NULL)
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
 * \return The honeypot IP found, NOK if nothing is found
 */
char * lookup_honeypot_addr( gchar *testkey, int list ) {
	
	/*! We test which list we want to search */
	if ( list == LIH ) {
	        /*! get the corresponding hih destination from the low interaction hash table */
	        char *hihdest;
	        hihdest = g_strdup((char *)g_hash_table_lookup(low_redirection_table, testkey));

	        if(!hihdest)
	                return NULL;
	        return hihdest;

	} else {
                /*! get the corresponding lih destination from the high interaction hash table */

		/*! Check first if the high_reciredtion_table is not null */
		if (high_redirection_table == NULL)
			return NULL;

                char *lihdest;
		lihdest = g_strdup((char *)g_hash_table_lookup(high_redirection_table, testkey));

                if(!lihdest)
                        return NULL;
                return lihdest;
	}
	return NULL;
}

/*! store_packet function
 \brief Store the current packet as part of the connection to replay it later. If this is the first packet of a communication, init its structure in the main B-Tree.
 *
 \param[in] current_packet_data: struct pkt_struct to work with
 \param[in] current_connection_data: struct conn_struct to work with
 *
 \return the position of the packet in the list in case of success, a negative value if storage has failed
 */
int store_packet(struct conn_struct *current_connection_data, struct pkt_struct *current_packet_data)
{
	current_packet_data->position = -1;
	/*! Lock the structure */
	g_static_rw_lock_writer_lock (&current_connection_data->lock);

	/*! Append current_packet_data to the singly-linked list of current_connection_data */
        current_connection_data->BUFFER = g_slist_append(current_connection_data->BUFFER, current_packet_data);

	/*! Get the packet position */
        current_packet_data->position = (g_slist_length(current_connection_data->BUFFER) - 1);

	/*! Unlock the structure */
        g_static_rw_lock_writer_unlock (&current_connection_data->lock);	
	
	char *logbuf = malloc(128);
	sprintf(logbuf,"store_packet():\tPacket stored in memory for connection %s\n", current_connection_data->key);
	L(NULL,logbuf,4,current_connection_data->id);
	/*! Return the position of the packet stored in the singly-linked list */
	return OK;
}


/*! match_old_value
 \brief called for each entry in the B-Tree, if a time value is upper to 121 sec and the connection is not marked as redirected, entry is deleted
 \param[in] key, a pointer to the current B-Tree key value
 \param[in] cur_conn, a pointer to the current B-Tree associated value
 \param[in] trash, user data, unused
 \return FALSE, to continue to traverse the tree (if TRUE is returned, traversal is stopped)
 */
int match_old_value(gpointer key, struct conn_struct *cur_conn, gpointer trash)
{
	GTimeVal t;
	g_get_current_time(&t);
	gint curtime = (t.tv_sec);
	GSList *current;
	struct pkt_struct* tmp;
	if(((curtime - cur_conn->access_time) > 120) || (cur_conn->state < INIT))
	{
		char *log = malloc(192);
		sprintf(log,"match_old_value():\tSingly linked list freed - tuple = %s\n", (char*)key);
		L(NULL,log,2,cur_conn->id);
		/*! lock the structure, this will never be unlocked */
		g_static_rw_lock_writer_lock (&cur_conn->lock);
		/*! remove the singly linked lists */

		current = cur_conn->BUFFER;
		do{
			tmp = (struct pkt_struct*) g_slist_nth_data ( current, 0 );
			free_packet_struct(tmp);
		}while((current = g_slist_next(current)) != NULL);
		g_slist_free(cur_conn->BUFFER);
		free(cur_conn->key_ext);
		free(cur_conn->key_lih);
		free(cur_conn->key_hih);
		/*! list the entry for later removal */
		g_ptr_array_add(entrytoclean, key);
	}
	return FALSE;
}

/*! remove_old_value
 \brief called for each entry in the pointer array, each entry is a key that is deleted from the B-Tree
 \param[in] key, a pointer to the current B-Tree key value stored in the pointer table
 \param[in] trash, user data, unused
 */
void remove_old_value(gpointer key, gpointer trash)
{
	char *log = malloc(192);
	sprintf(log,"remove_old_value():\tentry removed - tuple = %s\n", (char*)key);
	L(NULL,log,3,8);
	g_static_rw_lock_writer_lock (&rwlock);

	if (TRUE != g_tree_remove(conn_tree,key))
	{
		char *logbuf = malloc(64);
		sprintf("remove_old_value():\tError while removing tuple %s\n", (char*)key);
		L(NULL,logbuf,1,8);
		free(key);
	}
	g_static_rw_lock_writer_unlock (&rwlock);
}

/*! clean
 \brief watchman for the b_tree, wake up every 5 minutes and check every entries
 */
void clean()
{
	while (1)
	{
		/*! wake up every 121s (tcp timeout is 120s)*/
		g_usleep(999999);
		L("clean():\t\tcleaning\n",NULL,5,8);

		/*! init the table*/
		entrytoclean = g_ptr_array_new();

		/*! call the clean function for each value, delete the value if TRUE is returned */
		g_tree_traverse( conn_tree,(GHRFunc) match_old_value, G_IN_ORDER, NULL );

		/*! remove each key listed from the btree */
		g_ptr_array_foreach(entrytoclean,(GFunc) remove_old_value, NULL);

		/*! free the array */
		g_ptr_array_free(entrytoclean, TRUE);
	}
}





/*! setup_redirection
 \brief called for each connection being redirected to setup and start the redirection process
 \param[in] connection_data: redirected connection metadata
 \return OK when done, NOK in case of failure
 */
int setup_redirection(struct conn_struct *connection_data)
{
	char* hihaddr = lookup_honeypot_addr( connection_data->key_lih, LIH );

	if ( hihaddr != NULL )
	{
		/*! If a high interaction was found, we then check that it's not currently used by the same external host IP and Port */
		GString *key_hih_ext = g_string_new( "" );
		g_string_printf( key_hih_ext, "%s:%s", hihaddr, connection_data->key_ext );

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

			g_hash_table_insert (high_redirection_table, key_hih_ext->str, connection_data->key_lih );

			/*! We update the connection structure with the high interaction honeypot found */
			g_static_rw_lock_writer_lock (&connection_data->lock);

			connection_data->key_hih = hihaddr;
			gchar **tmp_ = g_strsplit( hihaddr, ":", 0);
			connection_data->hih.addr = htonl(addr2int( *tmp_ ));
			connection_data->hih.lih_addr = htonl(addr2int( connection_data->key_lih ));
			int tmp_port;
			sscanf(tmp_[1],"%i",&tmp_port);
			g_strfreev(tmp_);
			connection_data->hih.port = htons( (short)tmp_port );
			g_string_free(key_hih_ext,0);

			/*! We then update the status of the connection structure
			 */
			connection_data->state = REPLAY;
			L("setup_redirection():\tState updated to REPLAY\n",NULL, 2,connection_data->id);
			g_static_rw_lock_writer_unlock (&connection_data->lock);

			/*! We reset the LIH */
			reset_lih( connection_data );

			/*! We replay the first packets */
			struct pkt_struct* current;
			current = (struct pkt_struct*) g_slist_nth_data ( connection_data->BUFFER, connection_data->replay_id );
			while(current->origin == EXT)
			{
				forward(current);
				if(g_slist_next(g_slist_nth( connection_data->BUFFER, connection_data->replay_id )) == NULL)
				{
					connection_data->state = FORWARD;
					L("setup_redirection():\tState updated to FORWARD\n",NULL, 4, connection_data->id);
					return OK;
				}
				connection_data->replay_id++;
				current = (struct pkt_struct*) g_slist_nth_data ( connection_data->BUFFER, connection_data->replay_id );
			}
			/*! then define the next expected data */
			define_expected_data(current);
			connection_data->replay_id++;
		}
	}
	else
		return NOK;
	return OK;
}

