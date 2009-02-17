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

/*! \file sha1_mod.c
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

#include "modules.h"
#include "netcode.h"

/*! print_md
 \brief print a message digest in a file
 */
void print_md (gpointer key, gpointer value, FILE *fd)
{
	fprintf(fd,"%s\n",(char *)key);
}

/*! sha1_print
 \brief browse the research tables and print the fingerprint to a file
 */
void sha1_print()
{

	FILE *fd;
	int i;

	while(1)
	{
		sleep(10);
		L("sha1_print():\tsaving database\n",NULL,5,6);

		/*! open file in writing mode */
		if (NULL == (fd = fopen(g_hash_table_lookup(config, "sha1table"), "w")))
			continue;
		/*! print the header */
		fprintf(fd,"################################################################################\n################\t\tSHA1 SIGNATURES FILE\t\t################\n################################################################################\n");

		/*! for each database */
		for(i=0;i<=9;i++)
		{
			fprintf(fd,"#\n#~~~BDD%d~~~\n",i);
			g_hash_table_foreach(bdd[i],(GHFunc) print_md, fd);
		}
		fclose(fd);
	}
}

/*! init_mod_sha1
 \brief init the sha1 message digest module, fill up the databases */
int init_mod_sha1()
{
	L("init_mod_sha1():\tInitializing SHA-1 Module\n",NULL,3,6);

	/*! init OpenSSL SHA-1 engine */
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha1");
	int i,res;

	/*! init the signatures databases */
	bdd = malloc(10 * sizeof(GHashTable *));

	for(i=0;i<=9;i++)
	{
		if (NULL == (bdd[i] = g_hash_table_new(g_str_hash, g_str_equal)) )
		{
			L("init_mod_sha1():\tError while creating hash table...EXIT\n",NULL,2,6);
			return -1;
		}
	}

	/*! fill up the tables with the recorded signatures */
	FILE *fd;
	i = -1;
	char buf[BUFSIZ];
	int signcpt = 0;
	char *logbuf;
	char *tmp;

	if (NULL != (fd = fopen(g_hash_table_lookup(config, "sha1table"), "r")))
	{
		/*! for each database */
		tmp = malloc(41);
		while(fgets(buf, BUFSIZ, fd))
		{
			/*! select the hash table to load it */
			sscanf(buf,"#~~~BDD%i~~~",&i);
			if(i < 0 || i > 9 || strlen(buf) != 41 || buf[0] == '#')
				continue;
			res = sscanf(buf,"%[0-9a-f]",tmp);
			if(res != 1 || strlen(tmp) !=40 || NULL != g_hash_table_lookup(bdd[i],tmp))
				continue;
			g_hash_table_insert (bdd[i], tmp, tmp);
			tmp = malloc(41);

			signcpt++;
		}
		free(tmp);
		fclose(fd);
	}
	logbuf = malloc(64);
	sprintf(logbuf,"init_mod_sha1():\t%d signatures loaded\n",signcpt);
	L(NULL, logbuf, 2, 6);

	/*! create a thread that will print the fingerprint to a file every minute */
	if( g_thread_create_full ((void *)sha1_print, NULL, 0, FALSE, TRUE,G_THREAD_PRIORITY_LOW, NULL) == NULL)
		return -1;
	return 0;
}

/*! mod_sha1
 \param[in] args, struct that contain the node and the datas to process
 \param[in] user_data, not used
 *
 \param[out] set result to 0 if datas's fingerprint is found in search table, 1 if not
 */
void mod_sha1(struct mod_pool_args args)
{
	L("mod_sha1():\tModule called\n", NULL, 3, args.pkt->connection_data->id);

	char *submit;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len = 20, i=0;

	char *payload = malloc(args.pkt->data + 1);

	/*! get the payload from the packet */

	memcpy( payload, args.pkt->packet.payload, args.pkt->data);
	payload[args.pkt->data] = '\0';

	L("mod_sha1():\tcomputing payload digest\n", NULL, 4, args.pkt->connection_data->id);

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

	L("mod_sha1():\tSearching for fingerprint\n", NULL, 4, args.pkt->connection_data->id);

	/*! select the hash table for the research */
	sscanf(args.node->arg,"bdd%d",&i);
	if (NULL == g_hash_table_lookup(bdd[i],submit))
	{
		args.node->result = 1;
		g_hash_table_insert (bdd[i], submit, submit);
	}
	else
	{
		args.node->result = 0;
		free(submit);
	}

	if(args.node->result == 1)
	{
		L("mod_sha1():\tPACKET MATCH RULE\n", NULL, 2, args.pkt->connection_data->id);
	}
	else
		L("mod_sha1():\tPACKET DOES NOT MATCH RULE\n", NULL, 2, args.pkt->connection_data->id);

	/*! clean and exit */
	free(payload);
	return;
}

