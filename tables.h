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

#ifndef __TABLE_H__
#define __TABLE_H__

#include <glib.h>

//#include "netcode.h"
#include "types.h"

/*! \brief the pid of the main program
 */
long int mainpid;

/*!
 \def threading
 * Init value: OK
 * Set to NOK when honeybrid stops, used to terminate threads
 */
int threading;


/*! \brief security writing lock for the Binary Tree
*/
GStaticRWLock rwlock;

/*! \brief security writing lock for the dynamic high interaction redirection table
*/
GStaticRWLock hihlock;

/*! \brief global hash table that contain the values of the configuration file
 */
GHashTable *config;

/*! \brief global hash table that contain the static correspondance between LIH services et HIH services
 */
GHashTable *low_redirection_table;

/*! \brief global hash table that contain the dynamic correspondance between HIH services et LIH services
 */
GHashTable *high_redirection_table;

/*! \brief global integer table that contains the addresses of the low_interaction honeypots (integer version)
 */
GHashTable *low_honeypot_addr;

/*! \brief global integer table that contains the addresses of the high_interaction honeypots (integer version)
 */
GHashTable *high_honeypot_addr;

/*! \brief Balanced Binary Tree that keep meta informations about active connections
 *
 \param key, each entry is represented by the tuple of the connection (sourceIP+sourcePort+destIP+destPort)
 \param value, the associated value of an entry is a conn_struct structure
 */
GTree * conn_tree;

unsigned c_id;

/*! \brief pointer table for btree cleaning
 */
GPtrArray *entrytoclean;

int init_packet_struct( char *nf_packet, struct pkt_struct *new_packet_data);

int free_packet_struct( struct pkt_struct *pkt );

int get_current_struct(struct pkt_struct *current_packet_data, struct conn_struct **current_connection_data);

int test_honeypot_addr( char *testkey, int list );

char * lookup_honeypot_addr( gchar *testkey, int list );

int store_packet(struct conn_struct *current_connection_data, struct pkt_struct *current_packet_data);

void clean();

int setup_redirection(struct conn_struct *connection_data);

int match_old_value(gpointer key, struct conn_struct *cur_conn, gint *expiration_delay);

void remove_old_value(gpointer key, gpointer trash);

/*! \brief constants to define the origin of a packet
 */
#define EXT 0
#define LIH 1
#define HIH 2

/*! \brief constants to define the status of a connection
 */
#define INVALID 	0
#define INIT 		1
#define DECISION 	2
#define REPLAY 		3
#define FORWARD 	4
#define PROXY		5
#define DROP		6

/*!
  \def OK
 *
 * Return code when everything's fine
 */
#define OK		0

/*!
 *   \def NOK
 *
 * Return code when something when wrong
 */
#define NOK		-1

/*!
  \def TIMEOUT
  *
  * Return code when something took too much time
  */
#define TIMEOUT		-2


#endif //__TABLE_H__
