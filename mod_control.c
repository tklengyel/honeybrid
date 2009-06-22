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

/*! \file mod_control.c
 * \brief Source IP based control engine to rate limit high interaction honeypot
 *
 \author Robin Berthier 2009
 */

#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "tables.h"
#include "modules.h"
#include "netcode.h"

#include "mod_control.h"

/*!
 \def control_expiration control the time after which IP are removed from the control db
 */
int control_expiration = 600;
int max_packet = 1000;
int db_updated;

/*! expire_control
 \brief remove old controls from the hash
 */
int expire_control (gpointer key, gpointer value, gint *now)
{
	char *logbuf;
	struct control_info * info = (struct control_info *)value;
	/*! We reset the counter for IP that have been recorded since more than "control_expiration" seconds */
	if ((*now - info->first_seen) > control_expiration) {
		info->first_seen = info->last_seen;
		info->counter = 0;
		logbuf = malloc(64);
	        sprintf(logbuf,"expire_control():\tReseting counter for %s\n",(char *) key);
	        L(NULL, logbuf, 2, 6);
	}

	/*! We expire IP that have not manifested themselves for the past "control_expiration" seconds */
	if ((*now - info->last_seen) > control_expiration) {
		logbuf = malloc(64);
	        sprintf(logbuf,"expire_control():\tRemoving %s from list\n",(char *) key);
	        L(NULL, logbuf, 2, 6);
		free(value);
		return TRUE;
	}
	return FALSE;	
}

/*! print_control_info
 \brief print a message digest in a file
 */
void print_control_info (gpointer key, gpointer value, FILE *fd)
{
	struct control_info * info = (struct control_info *)value;
	fprintf(fd,"%s\t%d\t%d\t%d\n",(char *)key, info->counter, info->first_seen, info->last_seen);
}

/*! control_print
 \brief browse the research tables and print the fingerprint to a file
 */
void control_print()
{

	FILE *fd;

	GTimeVal t;
	gint *now;
	now = malloc(sizeof(gint));

	while( threading == OK )
	{
		/*! saving database of signatures every 100 seconds
		 */
		g_usleep(100000000);
	        g_get_current_time(&t);
	        *now = (t.tv_sec);

		if (db_updated > 0) {

			L("control_print():\tExpiring old controls\n",NULL,5,6);
			g_hash_table_foreach_remove(control_bdd,(GHRFunc) expire_control, now);

			L("control_print():\tsaving database\n",NULL,5,6);

			/*! open file in writing mode */
			if (NULL == (fd = fopen(g_hash_table_lookup(config, "controltable"), "w"))) {
				L("control_print():\terr... nowhere to save! Please configure controltable correctly.\n",NULL,5,6);
				continue;
			}
			/*! print the header */
			fprintf(fd,"### Source IP\n### (automatically generated every 100s by the control engine of Honeybrid)\n###\n");

			g_hash_table_foreach(control_bdd,(GHFunc) print_control_info, fd);
			fclose(fd);

			db_updated = 0;
		} else {
			L("control_print():\tNo need to save the control database\n",NULL,5,6);
		}
	}
	free(now);
}

/*! init_control
 \brief init the control module, fill up the databases */
int init_control()
{
	L("init_control():\tInitializing Control Engine\n",NULL,3,6);

	int i,res;
	int key_len = 255;
	int info_len = sizeof(struct control_info);

	db_updated = 1;

	/*! init the signatures databases */
	control_bdd = malloc(sizeof(GHashTable *));

	if (NULL == (control_bdd = g_hash_table_new(g_str_hash, g_str_equal)) )
	{
		L("init_control():\tError while creating hash table...EXIT\n",NULL,2,6);
		return -1;
	}

	/*! fill up the tables with the recorded signatures */
	FILE *fd;
	i = -1;
	char buf[BUFSIZ];
	int signcpt = 0;
	int sigerror = 0;
	char *logbuf;
	char *key;
	struct control_info * info;

	if (NULL != (fd = fopen(g_hash_table_lookup(config, "controltable"), "r")))
	{
		/*! for each database */
		key  = malloc(key_len);
		info = malloc(info_len);
		while(fgets(buf, BUFSIZ, fd))
		{
			if(strlen(buf) > (key_len + info_len + 10) || buf[0] == '#') {
				continue;
			}
			res = sscanf(buf,"%s\t%d\t%d\t%d",key, &info->counter, &info->first_seen, &info->last_seen);
			if(res != 4 || strlen(key) > key_len || NULL != g_hash_table_lookup(control_bdd,key)) {
				g_print("control init: \tDiscarded: res = %d, strlen(key) = %d and key_len = %d\n", res, strlen(key), key_len);
				sigerror++;
				continue;
			}
			g_hash_table_insert (control_bdd, key, info);

			key = malloc(key_len);
			info = malloc(info_len);
			signcpt++;
		}
		free(key);
		free(info);
		fclose(fd);
	}
	logbuf = malloc(64);
	sprintf(logbuf,"init_control():\t%d address(es) loaded\n",signcpt);
	L(NULL, logbuf, 2, 6);
	if (sigerror > 0) {
		logbuf = malloc(64);
		sprintf(logbuf,"init_control():\tERROR! %d address(es) could not be parsed\n",sigerror);
		L(NULL, logbuf, 2, 6);
	}

	/*! create a thread that will print the fingerprint to a file every minute */
	if( g_thread_create_full ((void *)control_print, NULL, 0, FALSE, TRUE,G_THREAD_PRIORITY_LOW, NULL) == NULL)
		return -1;
	return 0;
}

/*! control
 \param[in] pkts, struct that contain the packet to control
 \param[out] set result to 1 if rate limit reached, 0 otherwise
 */
int control(struct pkt_struct *pkt)
{
	if (pkt == NULL) {
		L("control():\tError, NULL packet\n", NULL, 3, 6);	
		return -1;
	}
	L("control():\tCalled\n", NULL, 3, 6);

	char *logbuf;
	struct control_info * info;
	gchar **key;

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	L("control():\tExtracting IP address\n", NULL, 3, 6);
	if ( pkt->key_src == NULL ) {
		L("control():\tError, NULL key_src\n", NULL, 3, 6);
		return -1;
	}
	/*! get the IP address from the packet */
        key = g_strsplit( pkt->key_src, ":", 0 );

	logbuf = malloc(256);
	sprintf(logbuf,"control():\tcontrolled IP is %s\n", key[0]);
	L(NULL, logbuf, 4, 6);

	L("control():\tSearching for this IP in the table\n", NULL, 4, 6);

	info = g_hash_table_lookup(control_bdd,key[0]);

	if (NULL == info)
	{
		info = malloc(sizeof(struct control_info));
		info->counter = 1;
		info->first_seen = now;
		info->last_seen = now;

		logbuf = malloc(256);
		sprintf(logbuf,"control():\tCreating a new entry for %s with counter: %d and time: %d\n",key[0], info->counter, info->first_seen);
		L(NULL, logbuf, 2, 6);

		g_hash_table_insert(control_bdd, key[0], info);
		db_updated = 1;
	}
	else
	{
		info->counter++;
		info->last_seen = now;
		db_updated = 1;

		logbuf = malloc(256);
		sprintf(logbuf,"control():\tUpdating an existing entry for %s with counter: %d and time: %d\n",key[0], info->counter, info->last_seen);
		L(NULL, logbuf, 2, 6);
	}

	/*! clean */
	//free(key);
	g_strfreev(key);

	if(info->counter > max_packet)
	{
		logbuf = malloc(256);
		sprintf(logbuf,"control():\tRate limit reached!\n");
		L(NULL, logbuf, 2, 6);
		return 1;
	}
	else {
		logbuf = malloc(256);
		sprintf(logbuf,"control():\tRate limit not reached\n");
		L(NULL, logbuf, 2, 6);
		return 0;
	}

}

