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

/*! \file source_mod.c
 * \brief Source IP based filtering Module for honeybrid Decision Engine
 *
 * This module is called by a boolean decision tree to filter attacker based on their IP address
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

#include "source_mod.h"

/*!
 \Def sourcedb_max, maximum number of databases
 */
int sourcedb_max = 32;
int expiration = 24*3600;
int db_updated;

/*! expire_source
 \brief remove old sources from the hash
 */
int expire_source (gpointer key, gpointer value, gint *now)
{
	struct source_info * info = (struct source_info *)value;
	if ((*now - info->last_seen) > expiration) {
		free(value);
		return TRUE;
	}
	return FALSE;	
}

/*! print_info
 \brief print a message digest in a file
 */
void print_info (gpointer key, gpointer value, FILE *fd)
{
	struct source_info * info = (struct source_info *)value;
	fprintf(fd,"%s\t%d\t%d\t%d\n",(char *)key, info->counter, info->first_seen, info->last_seen);
}

/*! sha1_print
 \brief browse the research tables and print the fingerprint to a file
 */
void source_print()
{

	FILE *fd;
	int i;

	GTimeVal t;
	gint *now;
	now = malloc(sizeof(gint));

	while( threading == OK )
	{
		/*! saving database of signatures every 10 seconds
		 */
		g_usleep(10000000);
	        g_get_current_time(&t);
	        *now = (t.tv_sec);

		if (db_updated > 0) {

			L("source_print():\tExpiring old sources\n",NULL,5,6);
			for(i=0; i<sourcedb_max; i++)
			{
				g_hash_table_foreach_remove(source_bdd[i],(GHRFunc) expire_source, now);
			}

			L("source_print():\tsaving database\n",NULL,5,6);

			/*! open file in writing mode */
			if (NULL == (fd = fopen(g_hash_table_lookup(config, "sourcetable"), "w"))) {
				L("source_print():\terr... nowhere to save! Please configure sourcetable correctly.\n",NULL,5,6);
				continue;
			}
			/*! print the header */
			fprintf(fd,"### Source IP\n### (automatically generated every 10s by the source module of Honeybrid)\n###\n");

			/*! for each database */
			for(i=0; i<sourcedb_max; i++)
			{
				fprintf(fd,"#~~~BDD%d~~~\n",i);
				g_hash_table_foreach(source_bdd[i],(GHFunc) print_info, fd);
			}
			fclose(fd);

			db_updated = 0;

		} else {
			L("source_print():\tNo need to save the source database\n",NULL,5,6);
		}
	}
	free(now);
}

/*! init_mod_source
 \brief init the source module, fill up the databases */
int init_mod_source()
{
	L("init_mod_source():\tInitializing Source Module\n",NULL,3,6);

	int i,res;
	int ip_len = 15;
	int info_len = sizeof(struct source_info);

	db_updated = 1;

	/*! init the signatures databases */
	source_bdd = malloc(sourcedb_max * sizeof(GHashTable *));

	for(i=0; i<sourcedb_max; i++)
	{
		if (NULL == (source_bdd[i] = g_hash_table_new(g_str_hash, g_str_equal)) )
		{
			L("init_mod_source():\tError while creating hash table...EXIT\n",NULL,2,6);
			return -1;
		}
	}

	/*! fill up the tables with the recorded signatures */
	FILE *fd;
	i = -1;
	char buf[BUFSIZ];
	int signcpt = 0;
	int sigerror = 0;
	char *logbuf;
	char *key;
	struct source_info * info;

	if (NULL != (fd = fopen(g_hash_table_lookup(config, "sourcetable"), "r")))
	{
		/*! for each database */
		key  = malloc(ip_len);
		info = malloc(info_len);
		while(fgets(buf, BUFSIZ, fd))
		{
			/*! select the hash table to load it */
			sscanf(buf,"#~~~BDD%i~~~",&i);
			if(i < 0 || i >= sourcedb_max || strlen(buf) < ip_len || strlen(buf) > (ip_len + info_len + 10) || buf[0] == '#') {
				continue;
			}
			res = sscanf(buf,"%s\t%d\t%d\t%d",key, &info->counter, &info->first_seen, &info->last_seen);
			if(res != 4 || strlen(key) > ip_len || NULL != g_hash_table_lookup(source_bdd[i],key)) {
				g_print("source init: \tDiscarded: res = %d, strlen(key) = %d and ip_len = %d\n", res, strlen(key), ip_len);
				sigerror++;
				continue;
			}
			g_hash_table_insert (source_bdd[i], key, info);

			key = malloc(ip_len);
			info = malloc(info_len);
			signcpt++;
		}
		free(key);
		free(info);
		fclose(fd);
	}
	logbuf = malloc(64);
	sprintf(logbuf,"init_mod_source():\t%d address(es) loaded\n",signcpt);
	L(NULL, logbuf, 2, 6);
	if (sigerror > 0) {
		logbuf = malloc(64);
		sprintf(logbuf,"init_mod_source():\tERROR! %d address(es) could not be parsed\n",sigerror);
		L(NULL, logbuf, 2, 6);
	}

	/*! create a thread that will print the fingerprint to a file every minute */
	if( g_thread_create_full ((void *)source_print, NULL, 0, FALSE, TRUE,G_THREAD_PRIORITY_LOW, NULL) == NULL)
		return -1;
	return 0;
}

/*! mod_source
 \param[in] args, struct that contain the node and the data to process
 \param[in] user_data, not used
 *
 \param[out] set result to 0 if attacker ip is found in search table, 1 if not
 */
void mod_source(struct mod_args args)
{
	L("mod_source():\tModule called\n", NULL, 3, args.pkt->connection_data->id);

	char *logbuf;
	struct source_info * info;
	int i, check, drop;
	char *type;
	//char *ip;
	gchar **key_src;

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	/*! get the IP address from the packet */
	key_src = g_strsplit( args.pkt->key_src, ":", 0 );

	logbuf = malloc(256);
	sprintf(logbuf,"mod_source():\tsource IP is %s\n", key_src[0]);
	L(NULL, logbuf, 4, args.pkt->connection_data->id);

	L("mod_source():\tSearching for the attacker IP in the table\n", NULL, 4, args.pkt->connection_data->id);

	/*! select the hash table for the research */
	type = malloc(64);
	check = sscanf(args.node->arg,"bdd%d,%s", &i, type);

	if (check != 2) {
		L("mod_source():\tError: module argument malformed!\n", NULL, 3, args.pkt->connection_data->id);
		args.node->result = 0;
		free(key_src);
		return;
	} 

	if (strcmp( type, "drop") == 0) {
		drop = -1;
	} else {
		drop = 0;
	}
	free(type);

	info = g_hash_table_lookup(source_bdd[i],key_src[0]);

	if (NULL == info)
	{
		args.node->result = 1;

		info = malloc(sizeof(struct source_info));
		info->counter = 1;
		info->first_seen = now;
		info->last_seen = now;

		logbuf = malloc(256);
		sprintf(logbuf,"mod_source():\tCreating a new entry for %s in bdd%d with counter: %d and time: %d\n",key_src[0], i, info->counter, info->first_seen);
		L(NULL, logbuf, 2, args.pkt->connection_data->id);

		g_hash_table_insert(source_bdd[i], key_src[0], info);
		db_updated = 1;
	}
	else
	{
		args.node->result = drop;

		info->counter++;
		info->last_seen = now;
		db_updated = 1;

		logbuf = malloc(256);
		sprintf(logbuf,"mod_source():\tUpdating an existing entry for %s in bdd%d with counter: %d and time: %d\n",key_src[0], i, info->counter, info->last_seen);
		L(NULL, logbuf, 2, args.pkt->connection_data->id);
	}

	if(args.node->result == 1)
	{
		logbuf = malloc(256);
		sprintf(logbuf,"mod_source():\tPACKET MATCH RULE for source(bdd%d)\n",i);
		L(NULL, logbuf, 2, args.pkt->connection_data->id);
	}
	else {
		logbuf = malloc(256);
		sprintf(logbuf,"mod_source():\tPACKET DOES NOT MATCH RULE for source(bdd%d)\n",i);
		L(NULL, logbuf, 2, args.pkt->connection_data->id);
	}

	/*! clean and exit */
	free(key_src);
	return;
}

