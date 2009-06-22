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

/*! \file mod_hash.c
 * \brief SHA 1 Module for honeybrid Decision Engine
 *
 * This module is called by a boolean decision tree to process a message digest and try to find it in a search table
 *
 *
 \author Julien Vehent, 2007
 \author Thomas Coquelin, 2008
 */

#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "tables.h"
#include "modules.h"
#include "netcode.h"

#include "mod_hash.h"

/*!
 \def sigdb_max
 */
int sigdb_max = 32;

/*!
 \def hash_id
 */
int hash_id;

int db_updated;

/*! print_md
 \brief print a message digest in a file
 */
void print_md (gpointer key, gpointer value, FILE *fd)
{
	//fprintf(fd,"%s %s\n",(char *)key, (char *)value);
	struct hash_info * info = (struct hash_info *)value;
        fprintf(fd,"%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", info->bdd_id, info->port, info->id, info->counter, info->first_seen, info->duration, info->packet, info->byte, (char *)key, info->ascii);
}

/*! hash_print
 \brief browse the research tables and print the fingerprint to a file
 */
void hash_print()
{

	FILE *fd;
	int i;

	while( threading == OK )
	{
		/*! saving database of signatures every 10 seconds
		 */
		g_usleep(10000000);

		if (db_updated > 0) {

			L("hash_print():\tsaving database\n",NULL,5,6);

			/*! open file in writing mode */
			if (NULL == (fd = fopen(g_hash_table_lookup(config, "hashtable"), "w"))) {
				L("hash_print():\terr... nowhere to save! Please configure hashtable correctly.\n",NULL,5,6);
				continue;
			}
			/*! print the header */
			fprintf(fd,"### Payload Hashes\n### (automatically generated every 10s by the hash module of Honeybrid)\n###\n");

			/*! for each database */
			for(i=0; i<sigdb_max; i++)
			{
				fprintf(fd,"#~~~BDD%d~~~\n",i);
				g_hash_table_foreach(hash_bdd[i],(GHFunc) print_md, fd);
			}
			fclose(fd);
		} else {
			 L("hash_print():\tNo need to save the source database\n",NULL,5,6);
		}
	}
}

/*! init_mod_hash
 \brief init the hash message digest module, fill up the databases */
int init_mod_hash()
{
	L("init_mod_hash():\tInitializing Hash Module\n",NULL,3,6);

	hash_id = 1;

	/*! init OpenSSL SHA-1 engine */
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha1");
	int i,res;
	int ascii_len = 64;
	int hash_len = 41;
	int info_len = sizeof(struct hash_info);

	db_updated = 1;

	/*! init the signatures databases */
	hash_bdd = malloc(sigdb_max * sizeof(GHashTable *));

	for(i=0; i<sigdb_max; i++)
	{
		if (NULL == (hash_bdd[i] = g_hash_table_new(g_str_hash, g_str_equal)) )
		{
			L("init_mod_hash():\tError while creating hash table...EXIT\n",NULL,2,6);
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
	struct hash_info * info;

	if (NULL != (fd = fopen(g_hash_table_lookup(config, "hashtable"), "r")))
	{
		/*! for each database */
		key   = malloc(hash_len);
		info = malloc(info_len);
		info->ascii = malloc(ascii_len);
		while(fgets(buf, BUFSIZ, fd))
		{
			/*! select the hash table to load it */
			sscanf(buf,"#~~~BDD%i~~~",&i);
			if(i < 0 || i >= sigdb_max || strlen(buf) < hash_len || strlen(buf) > (hash_len + info_len + ascii_len + 10) || buf[0] == '#') {
				continue;
			}
			//res = sscanf(buf,"%[0-9a-f] %[^\n]",tmp_key, tmp_value);
			res = sscanf(buf, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%[0-9a-f]\t%[^\n]", &info->bdd_id, &info->port, &info->id, &info->counter, &info->first_seen, &info->duration, &info->packet, &info->byte, key, info->ascii);

			if(res != 10 || strlen(key) !=(hash_len - 1) || NULL != g_hash_table_lookup(hash_bdd[i], key)) {
				sigerror++;
				continue;
			}
			g_hash_table_insert (hash_bdd[i], key, info);

			if (info->id > hash_id) {
				hash_id = (info->id + 1);
			}

			key = malloc(hash_len);
			info = malloc(info_len);
			info->ascii = malloc(ascii_len);
			signcpt++;
		}
		free(key);
		free(info->ascii);
		free(info);
		fclose(fd);
	}
	logbuf = malloc(64);
	sprintf(logbuf,"init_mod_hash():\t%d signature(s) loaded\n",signcpt);
	L(NULL, logbuf, 2, 6);
	if (sigerror > 0) {
		logbuf = malloc(64);
		sprintf(logbuf,"init_mod_hash():\tERROR! %d signature(s) could not be parsed\n",sigerror);
		L(NULL, logbuf, 2, 6);
	}

	/*! create a thread that will print the fingerprint to a file every minute */
	if( g_thread_create_full ((void *)hash_print, NULL, 0, FALSE, TRUE,G_THREAD_PRIORITY_LOW, NULL) == NULL)
		return -1;
	return 0;
}

/*! mod_hash
 \param[in] args, struct that contain the node and the datas to process
 \param[in] user_data, not used
 *
 \param[out] set result to 0 if datas's fingerprint is found in search table, 1 if not
 */
void mod_hash(struct mod_args args)
{
	L("mod_hash():\tModule called\n", NULL, 3, args.pkt->conn->id);

	/*! First, we make sure that we have data to work on */
	if (args.pkt->data == 0) {
		args.node->result = 0;
                args.node->info_result = -1;
		L("mod_hash():\tNo data to work on!\n", NULL, 3, args.pkt->conn->id);	
		return;
	}

	int ascii_len = 64;
	char *logbuf;
	int port = 0;

	char *submit;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len = 20, i=0;

	char *payload = malloc(args.pkt->data + 1);
	struct hash_info * info;
	char *ascii;	

	gchar **key_dst;
	char *position;
	int j,h,pos;

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	db_updated = 1;

	/*! get the IP address from the packet */
        key_dst = g_strsplit( args.pkt->key_dst, ":", 0 );

	/*! get the destination port */
	sscanf(key_dst[1], "%d", &port);

	/*! get the payload from the packet */
	memcpy( payload, args.pkt->packet.payload, args.pkt->data - 1);
	payload[args.pkt->data] = '\0';

	if (strlen(key_dst[0]) >= 7) {
		/*! replacing occurrences of the destination IP by a generic string */
		while(NULL != (position = strstr(payload, key_dst[0]))) {
			L("mod_hash():\tfound the dst ip in the payload! Replacing it...\n", NULL, 4, args.pkt->conn->id);

			pos = (int)(position-payload);	

			payload[pos+0] = '<';
			payload[pos+1] = 'A';
			payload[pos+2] = 'D';
			payload[pos+3] = 'D';
			payload[pos+4] = 'R';
			payload[pos+5] = '>';

			h=strlen(key_dst[0]) - 6;

			for(j=(pos+6); j<(strlen(payload)-h); j++) {
				payload[j] = payload[j+h];	
			}

			payload[strlen(payload)-h] = '\0';
		}
	}

	if (strlen(payload) < ascii_len) {
		ascii_len = strlen(payload);
	}
	ascii = malloc(ascii_len + 1);

	L("mod_hash():\tcomputing payload digest\n", NULL, 4, args.pkt->conn->id);

	/*! digest the payload */
	EVP_MD_CTX ctx;

	EVP_MD_CTX_init(&ctx);

	EVP_DigestInit_ex(&ctx, md, NULL);

	EVP_DigestUpdate(&ctx, payload, args.pkt->data - 2);

	EVP_DigestFinal_ex(&ctx, md_value, &md_len);

	EVP_MD_CTX_cleanup(&ctx);

	submit = malloc((md_len << 1)+1);

	for(i = 0; i < md_len; i++)
		sprintf(submit + (i<<1),"%02x",md_value[i]);

	L("mod_hash():\tcomputing payload ascii representation\n", NULL, 4, args.pkt->conn->id);

	///g_print("=============\n");
	for(i = 0; i < ascii_len; i++) {
		if (isprint(payload[i])) {
			sprintf(&ascii[i],"%c", payload[i]);
		} else {
			sprintf(&ascii[i],".");
		}
	}
	ascii[ascii_len] = '\0';

	logbuf = malloc(ascii_len+64);
	sprintf(logbuf,"mod_hash():\tASCII of %d char [%s]\n", ascii_len, ascii);
	L(NULL, logbuf, 4, args.pkt->conn->id);

	L("mod_hash():\tSearching for fingerprint\n", NULL, 4, args.pkt->conn->id);

	/*! select the hash table for the research */
	sscanf(args.node->arg,"bdd%d",&i);

	info = g_hash_table_lookup(hash_bdd[i],submit);

	if (NULL == info)
	{
		args.node->result = 1;
		
		info = malloc(sizeof(struct hash_info));
		info->ascii = malloc(ascii_len + 1);

		info->bdd_id = i;
		info->id = hash_id++;
		info->counter = 1;
		info->first_seen = now;
		info->duration = 0;
		info->port = port;
		info->packet = args.pkt->conn->count_data_pkt_from_intruder;
		info->byte = args.pkt->data;
		memcpy( info->ascii, ascii, ascii_len);
		info->ascii[ascii_len] = '\0';

		logbuf = malloc(256);
                sprintf(logbuf,"mod_hash():\tCreating a new entry in bdd%d with id %d and counter: %d and time: %d\n", info->bdd_id, info->id, info->counter, info->first_seen);
                L(NULL, logbuf, 2, args.pkt->conn->id);
		
		g_hash_table_insert (hash_bdd[i], submit, info);

		args.node->info_result = info->id;
	}
	else
	{
		args.node->result = 0;
		args.node->info_result = info->id;
		
		info->counter++;
		info->duration = (now - info->first_seen);

		logbuf = malloc(256);
                sprintf(logbuf,"mod_hash():\tUpdating the entry %d in bdd%d with counter: %d and time: %d\n", info->id, info->bdd_id, info->counter, info->duration);
                L(NULL, logbuf, 2, args.pkt->conn->id);

		g_free(submit);
		g_free(ascii);
	}

	if(args.node->result == 1)
	{
		logbuf = malloc(256);
		sprintf(logbuf,"mod_hash():\tPACKET MATCH RULE for hash(bdd%d) with hash %d\n",i, info->id);
		L(NULL, logbuf, 2, args.pkt->conn->id);
	}
	else {
		logbuf = malloc(256);
		sprintf(logbuf,"mod_hash():\tPACKET DOES NOT MATCH RULE for hash(bdd%d)\n",i);
		L(NULL, logbuf, 2, args.pkt->conn->id);
	}

	/*! clean and exit */
	g_free(payload);
	g_free(ascii);
	return;
}

