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

/*! \file decision_engine.c
 * \brief Decision Engine for honeybrid
 *
 * This engine creates boolean decision trees from a rule list and process incoming connection using those trees. If the tree return TRUE, the redirected value of the connection is set to 1.
 *
 *
 \author Julien Vehent, 2007
 \author Thomas Coquelin, 2008
 *
 */

#include <malloc.h>
#include <string.h>
#include <glib.h>

#include "decision_engine.h"
#include "netcode.h"
#include "modules.h"
#include "tables.h"
#include "log.h"


/*! build_subtree
 \param[in] expr, a part of the boolean equation
 *
 \brief recursively process the expression and creates the nodes */
struct node *DE_build_subtree(const gchar *expr)
{
	struct node *node;
	node = (struct node *) malloc(sizeof( struct node));
	node->module = NULL;

	/*! test presence of AND operator */
	char *op_pos_AND = strstr(expr,"AND");
	char *modname, *arg;

	/*! composed expression: separate the left part */
	if(NULL != op_pos_AND)
	{
		/*! split on "AND" operator */
		GRegex *regex;
		regex = g_regex_new ("AND\\s", 0, 0, NULL);
		gchar **and = g_regex_split(regex, expr, 0);
		/*! process left part of the AND */
		regex = g_regex_new ("(\\S+)(\\(\\S+\\))", 0, 0, NULL);
		gchar **left_side = g_regex_split(regex, and[0], 0);
		modname = g_strdup(left_side[1]);
		/*! remove first parenthesis */
		arg = g_strdup(left_side[2]);
		arg++;
		/*! do not copy last parenthesis */
		node->arg = g_strndup(arg, strlen(arg) -1);
		/*! call function with right side of expr */
		node->true = DE_build_subtree(and[1]);
		node->false = NULL;
	}
	/*! single module in expression, just add the leaf */
	else
	{
		GRegex *regex;
		regex = g_regex_new ("(\\S+)(\\(\\S+\\))", 0, 0, NULL);
		gchar **right_side = g_regex_split(regex, expr, 0);
		modname = g_strdup(right_side[1]);
		/*! remove first parenthesis */
		arg = g_strdup(right_side[2]);
		/*! do not copy last parenthesis */
		node->arg = g_strndup(arg + 1, strlen(arg + 1) -1);
		node->true = NULL;
		node->false = NULL;
		g_strfreev(right_side);
		free(arg);
	}

	/*! get module structure from DE_mod
	 */
	node->module = get_module(modname);
///	g_print("\tDE_build_subtree(): module = '%s' -> %p\n",modname,node->module);//toto
	
	free(modname);
	/*! return pointer to this leaf
	 */
	return node;
}



/*! DE_create_tree
 \brief build a boolean decision tree for a given equation
 *
 \param[in] equation a boolean equation
 *
 \return tree_root a pointer to the root of the boolean decision tree
 */
void *DE_create_tree(const gchar *equation)
{
	#ifdef DEBUG_
	g_print("\t|DE_create_tree(): creating tree for equation -> %s\n", equation);
	#endif

	/*! create a glib table to store the equation
	 */
	gchar **subgroups;

	subgroups = g_strsplit (equation, " OR ",0);

	tree.globalresult = -1;
	g_static_rw_lock_init( &tree.lock );

	/*! first subgroup
	 */
	tree.node = DE_build_subtree(subgroups[0]);

	/*! store address of the root
	 */
	void *tree_root;
	tree_root = (void *) tree.node;


	/*! for all the other subgroups
	 */
	int n=1;
	for (n=1;subgroups[n] != NULL; n++)
	{
		/*! get the pointer to the beginning of the new subtree
		 */
		struct node *headsubgroup;
		headsubgroup = DE_build_subtree(subgroups[n]);

		/*! connect new subtree to the previous one
		 *
		 * subtree (n) is a son of subtree(n-1)
		 */
		tree.node->false = headsubgroup;

		while(tree.node->true != NULL)
		{
			/*! and go to the next one
			 */
			if(tree.node->true != NULL)
				tree.node = tree.node->true;

			/*! in subtree (n-1), each FALSE branch is
			 * connected to the head of subtree(n)
			 */
			tree.node->false = headsubgroup;

		}

		/*! this subtree is done, so n become n-1
		 */
		tree.node = headsubgroup;
	}
	g_strfreev(subgroups);
	return tree_root;

}


/*! decide
 \brief decide upon a given paken if the connection is to be redirected or not
 \param[in] pkt: packet used to decide
 \return decision
 */

int decide(struct pkt_struct *pkt)
{
	struct mod_pool_args args;
	args.pkt = pkt;

	tree.globalresult = -1;
 	/*! start processing the tree from the root */
 	while (tree.globalresult == -1)
 	{
 		/*! init result value */
 		tree.node->result = -1;
		args.node = tree.node;
  		/*! call module */
 		tree.node->module(args);
 			/*! if result is true, forward to true node or exit with 1 */
 		if(tree.node->result == 1)
 			if(tree.node->true != NULL)
 				/*! go to next node */
 				tree.node = tree.node->true;
 			/*! end of the tree, exit */
 			else
 				tree.globalresult = 1;
 		/*! result is false, forward to false node or exit with 0 */
 		else
 			/*! go to the next subgroup */
 			if(tree.node->false != NULL)
 				tree.node = tree.node->false;
 			/*! end of the tree, exit */
 			else
 				tree.globalresult = 0;
 	}
	int res = tree.globalresult;
	return res;
}

/*! DE_submit_packet
 \brief handle connections being decided and submits packets for decision
 */

void DE_submit_packet()
{
	struct pkt_struct* pkt;
	while(1)
	if(DE_queue == NULL) {
		g_usleep(1);
	} 
	else
	{
		/* ROBIN DEBUG L("DE_submit_packet():\tCheking DE_queue: not null... Processing\n",NULL, 4,999);	*/
		pkt = (struct pkt_struct*) g_slist_nth_data ( DE_queue, 0 );
		char *logbuf=malloc(128);
		sprintf(logbuf,"DE_submit_packet():\tPacket pushed to DE: %s\n",pkt->connection_data->key);
		L(NULL,logbuf,3,pkt->connection_data->id);

		/*! search for the matching rule, if no matching rule exist for
		 * that connection, we do nothing */
		gchar **tuple;
		tuple = g_strsplit (pkt->connection_data->key, ":",0);
		GString *ruleid;
		ruleid = g_string_new("");

		/*! in 99% of the cases, the second part of the tuple will be the rule ID
		 * (because most connections are initiated from the outside) */
		g_string_printf(ruleid,"%s:%s",tuple[2],tuple[3]);

		/*! hash table lookup return the root */
		tree.node =(struct node *) g_hash_table_lookup(DE_rules, ruleid->str);
		if ( tree.node == NULL )
		{
			///ROBIN - 2009-02-17 - debug
			logbuf=malloc(128);	
			sprintf(logbuf,"DE_submit_packet():\tNo rule found using %s\n", ruleid->str);
			L(NULL, logbuf, 4, pkt->connection_data->id);

			/*! if rule not found with that ID, try with
			 * the other part of the tuple */
			ruleid = g_string_new("");
			g_string_printf(ruleid,"%s:%s", tuple[0], tuple[1]);
	
			/*! if no rule for that connection, do nothing */
			tree.node =(struct node *) g_hash_table_lookup(DE_rules, ruleid->str);

			///ROBIN - 2009-02-17 - debug
			if ( tree.node == NULL ) 
			{
				logbuf=malloc(128);
				sprintf(logbuf,"DE_submit_packet():\tNo rule found using %s\n",ruleid->str);
				L(NULL, logbuf, 4, pkt->connection_data->id);
			}
		}

		/*! we don't need that anymore */
		g_string_free(ruleid, TRUE);
		g_strfreev(tuple);
		int decision = -1;
		int res;
 		if (tree.node != NULL)
	 	{
			logbuf=malloc(128);
			sprintf(logbuf,"DE_submit_packet():\tRule available for this connection -> %s\n",pkt->connection_data->key);
			L(NULL,logbuf,3,pkt->connection_data->id);
			
			if( (pkt->origin == EXT) && (pkt->data > 0) )
			{
				L("DE_submit_packet():\tDeciding\n",NULL,4,pkt->connection_data->id);
				decision = decide(pkt);
				if(decision == 1)
				{
					logbuf=malloc(128);
					sprintf(logbuf,"DE_submit_packet():\tDecision is REDIRECT - tuple = %s\n",pkt->connection_data->key);
					L(NULL,logbuf,2,pkt->connection_data->id);
					res = setup_redirection(pkt->connection_data);
					if(res != OK)
						L("DE_submit_packet():\t setup_redirection() failed",NULL, 1,pkt->connection_data->id);
				}
				else
				{
					send_raw(pkt->packet.ip);
					logbuf=malloc(128);
					sprintf(logbuf,"DE_submit_packet():\tDecision is NOT REDIRECT - tuple = %s\n",pkt->connection_data->key);
					L(NULL,logbuf,2,pkt->connection_data->id);
				}
			}
			else
				send_raw(pkt->packet.ip);
		}
		///ROBIN - 2009-02-17 - debug
		else {
			L("DE_submit_packet():\tNo rule could be found for this connection... nothing to do\n",NULL,3,pkt->connection_data->id);
		}


		g_static_rw_lock_writer_lock ( &DE_queue_lock );
		DE_queue = g_slist_delete_link(DE_queue, DE_queue);
		g_static_rw_lock_writer_unlock ( &DE_queue_lock );
	}
}


/*! DE_push_pkt
 \brief push packet to the DE_submit_pkt queue
 \param[in] pkt: packet to push
 \return OK
 */

int DE_push_pkt(struct pkt_struct *pkt)
{
	L("DE_push_pkt():\tPushing packet to DE (locking DE_queue_lock)\n",NULL, 4,pkt->connection_data->id);
	g_static_rw_lock_writer_lock ( &DE_queue_lock );
	DE_queue = g_slist_append(DE_queue, (gpointer*) pkt);
	g_static_rw_lock_writer_unlock ( &DE_queue_lock );
	L("DE_push_pkt():\tPacket pushed to DE (unlocked DE_queue_lock)\n",NULL, 4,pkt->connection_data->id);
	return OK;
}

