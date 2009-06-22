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
	node = (struct node *) malloc(sizeof( struct node)); /// TODO: to be freed when destroying DE_rules
	node->module = NULL;

	/*! test presence of AND operator */
	char *op_pos_AND = strstr(expr,"AND");
	char *modname, *arg;

	/*! composed expression: separate the left part */
	if(NULL != op_pos_AND)
	{

		#ifdef DEBUG
       		g_print("\tDE_build_subtree():\tFound the AND operator, splitting...\n");
	        #endif

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
		g_regex_unref(regex);
	}
	/*! single module in expression, just add the leaf */
	else
	{

		#ifdef DEBUG
       		g_print("\tDE_build_subtree():\tNo operator found in '%s'\n", expr);
	        #endif

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
		g_regex_unref(regex);
	}

	/*! get module structure from DE_mod
	 */
	node->module = get_module(modname);
	node->module_name = g_string_new(NULL);
	g_string_printf(node->module_name, "%s",modname);
	//#ifdef DEBUG_
	g_print("\tDE_build_subtree(): module = '%s' -> %p\n",modname,node->module);
	//#endif
	
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
	#ifdef DEBUG
	g_print("\tDE_create_tree():\tcreating tree for equation -> %s\n", equation);
	#endif

	/*! create a glib table to store the equation
	 */
	gchar **subgroups;

	subgroups = g_strsplit (equation, " OR ",0);

	tree.globalresult = -1;
	tree.proxy = 0;
	tree.drop = 0;
	///tree.decision = g_string_new(NULL);

	g_static_rw_lock_init( &tree.lock );

	/*! first subgroup
	 */
	tree.node = DE_build_subtree(subgroups[0]);
	
	///tree.node->expr = malloc(512); ///TODO: seems to be incorrectly freed...	
	///sprintf( tree.node->expr, "%s", equation);

	/*! store address of the root
	 */
	void *tree_root;
	tree_root = (void *) tree.node;


	/*! for all the other subgroups
	 */
	int n=1;
	for (n=1;subgroups[n] != NULL; n++)
	{
		#ifdef DEBUG
		g_print("\tDE_create_tree():\tAnalyzing subgroup %i: '%s'\n", n, subgroups[n]);
		#endif
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

	L("decide():\tCalled\n",NULL,4,pkt->conn->id);

	struct mod_args args;
	args.pkt = pkt;

	tree.globalresult = -1;
 	/*! start processing the tree from the root */
 	while (tree.globalresult == -1)
 	{
 		/*! init result value */
 		tree.node->result = -1;
 		tree.node->info_result = 0;
		args.node = tree.node;
  		/*! call module */

		if (tree.node->module == NULL) {
			L("decide():\tERROR! tree.node->module is NULL\n",NULL,4,pkt->conn->id);
			return -1;
		}

 		tree.node->module(args);
 		/*! if result is true, forward to true node or exit with 1 */
 		if(tree.node->result >= 1) {
			/*! update decision_rule */
			///g_static_rw_lock_writer_lock (&pkt->conn->lock);
			if (tree.node->info_result != 0) {
				g_string_append_printf(pkt->conn->decision_rule, "+%s@%s:%d;", tree.node->module_name->str, args.node->arg, tree.node->info_result);
			} else {
				g_string_append_printf(pkt->conn->decision_rule, "+%s@%s;", tree.node->module_name->str, args.node->arg);
			}
			///g_static_rw_lock_writer_unlock (&pkt->conn->lock);

			/*! result == 2 indicates that it's accepted but we should proxy, not replay */
			if (tree.node->result == 2) {
				tree.proxy = 1;
			}


 			if(tree.node->true != NULL)
 				/*! go to next node */
 				tree.node = tree.node->true;
 			/*! end of the tree, exit */
 			else
 				tree.globalresult = 1;
 		/*! result is false, forward to false node or exit with 0 */
 		} else {
			/*! result == -1 indicates that we have to drop this connection forever */
			if (tree.node->result == -1) {
				tree.drop = 1;
			}

			///g_static_rw_lock_writer_lock (&pkt->conn->lock);
			if (tree.node->info_result != 0) {
				g_string_append_printf(pkt->conn->decision_rule, "-%s@%s:%d;", tree.node->module_name->str, args.node->arg, tree.node->info_result);
			} else {
				g_string_append_printf(pkt->conn->decision_rule, "-%s@%s;", tree.node->module_name->str, args.node->arg);
			}
			///g_static_rw_lock_writer_unlock (&pkt->conn->lock);

 			/*! go to the next subgroup */
 			if(tree.node->false != NULL)
 				tree.node = tree.node->false;
 			/*! end of the tree, exit */
 			else
 				tree.globalresult = 0;
		}
 	}
	int res = tree.globalresult;
	return res;
}

/*! DE_process_packet
 \brief submit packets for decision using decision rules and decision modules */
void DE_process_packet(struct pkt_struct *pkt) 
{
	char *logbuf=malloc(256);
	sprintf(logbuf,"DE_submit_packet():\tPacket pushed to DE: %s\n",pkt->conn->key);
	L(NULL,logbuf,3,pkt->conn->id);

	/*! search for the matching rule, if no matching rule exist for
	 * that connection, we do nothing */
	gchar **tuple;
	tuple = g_strsplit (pkt->conn->key, ":", 0);
	GString *ruleid;
	ruleid = g_string_new("");

	/*! small hack to be able to define rule for multiple IP at once
	 */
	gchar **dbyte, **sbyte;
	sbyte = g_strsplit (tuple[0], ".", 0);
	dbyte = g_strsplit (tuple[2], ".", 0);
	GString *classA, *classB, *classC;
	classA = g_string_new("");
	classB = g_string_new("");
	classC = g_string_new("");

	/*! in 99% of the cases, the second part of the tuple will be the rule ID
	 * (because most connections are initiated from outside) 
	 * tuple[2] is destination ip (should be honeyd ip)
	 * tuple[3] is destination port (should be port attacked)
	 */
	g_string_printf(ruleid,"%s:%s",tuple[2],tuple[3]);
	g_string_printf(classA,"%s.0.0.0:%s",dbyte[0],tuple[3]);
	g_string_printf(classB,"%s.%s.0.0:%s",dbyte[0],dbyte[1],tuple[3]);
	g_string_printf(classC,"%s.%s.%s.0:%s",dbyte[0],dbyte[1],dbyte[2],tuple[3]);

	/*! hash table lookup return the root */
	tree.node =(struct node *) g_hash_table_lookup(DE_rules, ruleid->str);

	/*! we then try by increasing the range of IP: */
	if ( tree.node == NULL)
		 tree.node =(struct node *) g_hash_table_lookup(DE_rules, classC->str);
	if ( tree.node == NULL)
		 tree.node =(struct node *) g_hash_table_lookup(DE_rules, classB->str);
	if ( tree.node == NULL)
		 tree.node =(struct node *) g_hash_table_lookup(DE_rules, classA->str);

	if ( tree.node == NULL )
	{
		///ROBIN - 2009-02-17 - debug
		logbuf=malloc(256);
		sprintf(logbuf,"DE_submit_packet():\tNo rule found using %s\n", ruleid->str);
		L(NULL, logbuf, 4, pkt->conn->id);

		/*! if rule not found with that ID, try with
		 * the other part of the tuple 
		 * tuple[0] is source IP
		 * tuple[1] is source port
		 */
		ruleid = g_string_new("");
		classA = g_string_new("");
		classB = g_string_new("");
		classC = g_string_new("");
		g_string_printf(ruleid,"%s:%s", tuple[0], tuple[1]);
	g_string_printf(classA,"%s.0.0.0:%s",sbyte[0],tuple[3]);
		g_string_printf(classB,"%s.%s.0.0:%s",sbyte[0],sbyte[1],tuple[3]);
		g_string_printf(classC,"%s.%s.%s.0:%s",sbyte[0],sbyte[1],sbyte[2],tuple[3]);
	
		/*! if no rule for that connection, do nothing */
		tree.node =(struct node *) g_hash_table_lookup(DE_rules, ruleid->str);

		/*! we then try by increasing the range of IP: */
		if ( tree.node == NULL)
			 tree.node =(struct node *) g_hash_table_lookup(DE_rules, classC->str);
		if ( tree.node == NULL)
			 tree.node =(struct node *) g_hash_table_lookup(DE_rules, classB->str);
		if ( tree.node == NULL)
			 tree.node =(struct node *) g_hash_table_lookup(DE_rules, classA->str);

		///ROBIN - 2009-02-17 - debug
		if ( tree.node == NULL ) 
		{
			logbuf=malloc(256);
			sprintf(logbuf,"DE_submit_packet():\tNo rule found using %s\n",ruleid->str);
			L(NULL, logbuf, 4, pkt->conn->id);
		}
	}

	/*! we don't need that anymore */
	g_string_free(ruleid, TRUE);
	g_string_free(classA, TRUE);
	g_string_free(classB, TRUE);
	g_string_free(classC, TRUE);
	g_strfreev(tuple);
	g_strfreev(dbyte);
	g_strfreev(sbyte);

	int decision = -1;
	int res;
 		if (tree.node != NULL)
	 	{
		logbuf=malloc(256);
		sprintf(logbuf,"DE_submit_packet():\tRule available for this connection -> %s\n",pkt->conn->key);
		L(NULL,logbuf,3,pkt->conn->id);
		
		///ROBIN - TODO: this condition will be revised soon to include packets from LIH and packets without payload (2009-03-27 19:50)
		///if( (pkt->origin == EXT) && (pkt->data > 0) )
		if( (pkt->origin == EXT) && (pkt->data >= MIN_DECISION_DATA ) )
		{
			L("DE_submit_packet():\tDeciding\n",NULL,4,pkt->conn->id);
			decision = decide(pkt);
			if(decision == 1)
			{
				/*! We lock the structure because we will modify it */
				///g_static_rw_lock_writer_lock (&pkt->conn->lock);

				if (tree.proxy == 0) {
					logbuf=malloc(256);
					sprintf(logbuf,"DE_submit_packet():\tDecision is REDIRECT - tuple = %s\n",pkt->conn->key);
					L(NULL,logbuf,2,pkt->conn->id);

					/*! we update connection statistics */	
					pkt->conn->decision_packet_id = pkt->conn->total_packet;
					///sprintf(pkt->conn->decision_rule, "(+)%s", tree.node->expr);
				///sprintf(pkt->conn->decision_rule, "(+)%s", tree.node->expr);

					/*! we do not release the packet, but we start the replay process */
					res = setup_redirection(pkt->conn);
					if(res != OK) {
						L("DE_submit_packet():\t setup_redirection() failed\n",NULL, 1,pkt->conn->id);
					}
				} else {
					logbuf=malloc(256);
                                                sprintf(logbuf,"DE_submit_packet():\tDecision is PROXY - tuple = %s\n",pkt->conn->key);
                                                L(NULL,logbuf,2,pkt->conn->id);

					/*! we update connection statistics */
                                                pkt->conn->decision_packet_id = pkt->conn->total_packet;
                                                ///sprintf(pkt->conn->decision_rule, "(+)%s", tree.node->expr);	///Problem: only the last inspected node is parsed!
                                                ///sprintf(pkt->conn->decision_rule, "(+)proxy()");	///Problem: only the last inspected node is parsed!

					/*! we update the state of the connection to PROXY */
					pkt->conn->state = PROXY;

					/*! we release the packet */
					send_raw(pkt->packet.ip);

					/* We have to put back the proxy mode to 0 */
					tree.proxy = 0;
				}

				///g_static_rw_lock_writer_unlock (&pkt->conn->lock);

			}
		else
			{
				if (tree.drop == 1) {
					logbuf=malloc(256);
                                                sprintf(logbuf,"DE_submit_packet():\tDecision is DROP - tuple = %s\n",pkt->conn->key);
                                                L(NULL,logbuf,2,pkt->conn->id);

					/*! We lock the structure because we will modify it */
	                                        ///g_static_rw_lock_writer_lock (&pkt->conn->lock);	
					pkt->conn->state = DROP;
					///g_static_rw_lock_writer_unlock (&pkt->conn->lock);

					/* We have to put back the drop mode to 0 */
					tree.drop = 0;
				} else {
					/*! we release the packet */
					send_raw(pkt->packet.ip);
					///g_static_rw_lock_writer_lock (&pkt->conn->lock);
					///sprintf(pkt->conn->decision_rule, "(-)%s", tree.node->expr);
					///g_static_rw_lock_writer_unlock (&pkt->conn->lock);
	
					logbuf=malloc(256);
					sprintf(logbuf,"DE_submit_packet():\tDecision is NOT REDIRECT - tuple = %s\n",pkt->conn->key);
					L(NULL,logbuf,2,pkt->conn->id);
				}
			}
		}
		else {
			L("DE_submit_packet():\tPacket is not from EXT or does not carry enough data... nothing to do\n",NULL,3,pkt->conn->id);
		/*! We release the packet */
			send_raw(pkt->packet.ip);
		}
	}
	else {
		L("DE_submit_packet():\tNo rule could be found for this connection... nothing to do\n",NULL,3,pkt->conn->id);
		///g_static_rw_lock_writer_lock (&pkt->conn->lock);
		g_string_assign(pkt->conn->decision_rule, "NoRule;");
		///g_static_rw_lock_writer_unlock (&pkt->conn->lock);
	}
}

/*! DE_submit_packet
 \brief handle connections being decided and submits packets for decision
 */
void DE_submit_packet()
{
    struct pkt_struct* pkt;

    while( threading == OK ) 
    {
	if(DE_queue == NULL) {
		g_usleep(1);
	} 
	else
	{
		pkt = (struct pkt_struct*) g_slist_nth_data ( DE_queue, 0 );
		DE_process_packet(pkt);

		/*! Now that this entry was processed, we can remove it from the DE queue */
		g_static_rw_lock_writer_lock ( &DE_queue_lock );
		DE_queue = g_slist_delete_link(DE_queue, DE_queue);
		g_static_rw_lock_writer_unlock ( &DE_queue_lock );
	}
    }
}

/*! DE_push_pkt
 \brief push packet to the DE_submit_pkt queue
 \param[in] pkt: packet to push
 \return OK */
void DE_push_pkt(struct pkt_struct *pkt)
{
	g_printerr("%s Pushing packet to DE (locking DE_queue_lock)\n", H(pkt->conn->id));
	g_static_rw_lock_writer_lock ( &DE_queue_lock );
	DE_queue = g_slist_append(DE_queue, (gpointer*) pkt);
	g_static_rw_lock_writer_unlock ( &DE_queue_lock );
	g_printerr("%s Packet pushed to DE (unlocked DE_queue_lock)\n", H(pkt->conn->id));
}

