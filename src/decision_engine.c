/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
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

/*! like strcmp */
int intcmp(gconstpointer v1, gconstpointer v2, gpointer extra) {
	return (*(uint32_t *) v1 < (*(uint32_t *) v2) ? 1 :
			(*(uint32_t *) v1 == (*(uint32_t *) v2)) ? 0 : -1);
}

/*! build_subtree
 \param[in] expr, a part of the boolean equation
 *
 \brief recursively process the expression and creates the nodes */
struct node *DE_build_subtree(const gchar *expr) {
	struct node *node;
	node = (struct node *) malloc(sizeof(struct node)); /// TODO: to be freed when destroying DE_rules
	node->module = NULL;
	char *modname;
	char *function;
	void* function_pointer;

	/*! test presence of AND operator */
	GRegex *and_regex = g_regex_new("\\sAND\\s", G_REGEX_CASELESS, 0, NULL);

	/*! composed expression: separate the left part */
	if (TRUE == g_regex_match(and_regex, expr, 0, NULL)) {
#ifdef DEBUG
		g_print("\t\tFound the AND operator, splitting...\n");
#endif

		/*! split on "AND" operator */
		gchar **and = g_regex_split(and_regex, expr, 0);
		/*! process left part of the AND */
		modname = g_strdup(and[0]);
		/*! call function with right side of expr */
		node->true = DE_build_subtree(and[1]);
		node->false = NULL;
	} else {
		/*! single module in expression, just add the leaf */

#ifdef DEBUG
		g_print("\t\tNo operator found in '%s'\n", expr);
#endif

		modname = g_strdup(expr);
		node->true = NULL;
		node->false = NULL;
	}

	/*! get module structure from DE_rules
	 */
	if ((node->arg = (GHashTable *) g_hash_table_lookup(module, modname))
			== NULL) {
		errx(1, "%s: Module '%s' unknown!", __func__, modname);
	}
	if ((function = (char *) g_hash_table_lookup(node->arg, "function")) == NULL) {
		errx(1, "%s: Module function undefined!", __func__);
	}
	if ((function_pointer = (void *) g_hash_table_lookup(node->arg,
			"function_pointer")) == NULL) {
		errx(1, "%s: Module function pointer undefined!", __func__);
	}

	node->module = function_pointer;
	node->module_name = g_string_new(NULL);
	node->function = g_string_new(NULL);
	g_string_printf(node->module_name, "%s", modname);
	g_string_printf(node->function, "%s", function);

	//#ifdef DEBUG
	g_print(
			"\t\tModule table %p (node arg: %p): Module function at %p '%s' defined at address %p\n",
			module, node->arg, function, function, node->module);
	//#endif

	//#ifdef DEBUG_
	//g_print("\tmodule = %s.%s()\n",node->module_name->str, node->function->str);
	//#endif

	g_regex_unref(and_regex);

	/*! return pointer to this leaf  */
	return node;
}

/*! DE_create_tree
 \brief build a boolean decision tree for a given equation
 *
 \param[in] equation a boolean equation
 *
 \return tree_root a pointer to the root of the boolean decision tree
 */
struct node *DE_create_tree(const gchar *equation) {

	/*! create a glib table to store the equation */
	gchar **subgroups;

	GRegex *or_regex = g_regex_new("\\sOR\\s", G_REGEX_CASELESS, 0, NULL);
	subgroups = g_regex_split(or_regex, equation, 0);

#ifdef DEBUG
	g_print("\t\tcreating tree at %p for equation -> %s\n", tree, equation);
#endif

	struct node *node = DE_build_subtree(subgroups[0]);

	/*! for all the other subgroups */
	int n = 1;
	for (n = 1; subgroups[n] != NULL; n++) {
		//#ifdef DEBUG
		g_print("\t\tAnalyzing subgroup %i: '%s'\n", n, subgroups[n]);
		//#endif

		/*! get the pointer to the beginning of the new subtree */
		struct node *headsubgroup;
		headsubgroup = DE_build_subtree(subgroups[n]);

		/*! connect new subtree to the previous one
		 * subtree (n) is a son of subtree(n-1) */
		node->false = headsubgroup;

		while (node->true != NULL) {
			/*! and go to the next one */
			if (node->true != NULL)
				node = node->true;

			/*! in subtree (n-1), each FALSE branch is
			 * connected to the head of subtree(n) */
			node->false = headsubgroup;

		}

		/*! this subtree is done, so n become n-1 */
		node = headsubgroup;
	}
	g_strfreev(subgroups);

	return node;

}

/*! decide
 \brief decide upon a given paken if the connection is to be redirected or not
 \param[in] pkt: packet used to decide
 \param[in] hih_search: which HIH are we testing (if it's a HIH, -1 otherwise)
 \return decision
 */

void decide(struct decision_holder *decision) {

	struct mod_args args;
	args.pkt = decision->pkt;
	args.backend_test = decision->backend_test;
	args.backend_use = decision->backend_use;

	/*! globalresult is used to store the final result of the boolean equation of module
	 3 possible outcome:
	 "-1" means "can't decide, needs more data to decide"
	 "0" means "reject"
	 "1" means "accept"
	 */

	decision->result = -2;

	/*! start processing the tree from the root */
	while (decision->result == -2) {
		/*! node->result is used to store the outcome of an individual module */
		decision->node->result = -1;
		/*! node->info_result is used to store additional information about the decision */
		decision->node->info_result = 0;

		args.node = decision->node;

		/*! call module */
		if (decision->node->module == NULL) {
			g_printerr("%s Error! decision->node->module is NULL\n",
					H(decision->pkt->conn->id));
			break;
		} else {
			g_printerr("%s >> Calling module %s at address %p\n",
					H(decision->pkt->conn->id),
					decision->node->module_name->str, decision->node->module);
			//tree.node->module(args);
			//Test of new function "run_module" to prevent segmentation fault occurring at the previous line
			run_module(decision->node->function->str, &args);
			g_printerr("%s >> Done, result is %d\n", H(decision->pkt->conn->id),
					decision->node->result);
		}

		switch (decision->node->result) {
		case 1: /*! if result is true, forward to true node or exit with 1 */
			/*! update decision_rule information */
			if (decision->node->info_result != 0)
				g_string_append_printf(decision->pkt->conn->decision_rule,
						"+%s:%d;", decision->node->module_name->str,
						decision->node->info_result);
			else
				g_string_append_printf(decision->pkt->conn->decision_rule,
						"+%s;", decision->node->module_name->str);

			/* Global multi-hih module that tells which HIH ID to use */
			if (args.backend_use != 0) {
				decision->backend_use = args.backend_use;
				g_printerr("%s >> Module suggested using HIH %u\n",
						H(decision->pkt->conn->id), args.backend_use);
			}

			if (decision->node->true != NULL)
				decision->node = decision->node->true; /*! go to next node */
			else
				decision->result = 1; /*! end of the tree, exit */
			break;
		case -1:
			if (decision->node->info_result < 0)
				g_string_append_printf(decision->pkt->conn->decision_rule,
						"?%s:%d;", decision->node->module_name->str,
						decision->node->info_result);
			else
				g_string_append_printf(decision->pkt->conn->decision_rule,
						"?%s;", decision->node->module_name->str);

			decision->result = -1; /*! end of the tree, exit */
			break;
		default: /*! result is false (result == 0), forward to false node or exit with 0 */
			if (decision->node->info_result < 0)
				g_string_append_printf(decision->pkt->conn->decision_rule,
						"-%s:%d;", decision->node->module_name->str,
						decision->node->info_result);
			else
				g_string_append_printf(decision->pkt->conn->decision_rule,
						"-%s;", decision->node->module_name->str);

			if (decision->node->false != NULL)
				decision->node = decision->node->false; /*! go to the next subgroup */
			else
				decision->result = 0; /*! end of the tree, exit */
			break;
		}
	}
}

void get_decision(struct decision_holder *decision) {

	if (decision->node == NULL) {
		g_printerr("%s rule is NULL for state %d on target %p\n",
				H(decision->pkt->conn->id), decision->pkt->conn->state,
				decision->pkt->conn->target);
		decision->result = DE_NO_RULE;
	} else {
		g_printerr("%s Rule available, deciding...\n",
				H(decision->pkt->conn->id));
		decide(decision);
		decision->pkt->conn->decision_packet_id =
				decision->pkt->conn->total_packet;
	}
}

int get_decision_backend(gpointer key, gpointer value, gpointer data) {
	struct decision_holder *decision = (struct decision_holder *) data;
	decision->backend_test = *(uint32_t *) key;
	decision->node = (struct node *) value;
	get_decision(decision);

	/* Stop searching on the first accept */
	if (decision->result == 1) {
		decision->backend_use = *(uint32_t *) key;
		return TRUE;
	} else {
		return FALSE;
	}
}

/*! DE_process_packet
 \brief submit packets for decision using decision rules and decision modules */
int DE_process_packet(struct pkt_struct *pkt) {

	/* This structure holds the result of LIH/HIH/CONTROL equations */
	/* The flow is get_decision->decide->run_module */
	/* For multi-HIH backends a module can set the backend_use variable in the mod_args structure to give the HIH ID */
	/* Otherwise each HIH backend can be checked one-by-one */

	struct decision_holder decision;
	decision.pkt = pkt;
	decision.result = DE_REJECT;
	decision.backend_test = 0;
	decision.backend_use = 0;

	int statement = 0; /*! default is to return "drop" to the QUEUE */

	g_printerr("%s Packet pushed to DE: %s\n", H(pkt->conn->id),
			pkt->conn->key);

	switch (pkt->conn->state) {
	case INIT:
		/* If we're in INIT, we need to get the "accept" rule from the frontend definition of the target */
		decision.node = (struct node *) pkt->conn->target->front_rule;

		get_decision(&decision);
		break;
	case DECISION:
		/* If we already passed INIT, we need to get the "redirect" rule from the backend definition of the target */

		/* Check if global rule for multi-hih available */
		if (pkt->conn->target->back_picker != NULL) {
			decision.node = pkt->conn->target->back_picker;
			get_decision(&decision);

			if (decision.result == DE_ACCEPT && decision.backend_use != 0) {
				// Back picker gave us a HIH, run it's test (if any)
				g_printerr("%s Global backend rule gave us a HIH: %u\n",
						H(pkt->conn->id), decision.backend_use);
				decision.node = (struct node *) g_tree_lookup(
						pkt->conn->target->back_rules, &(decision.backend_use));

				if (decision.node != NULL) {
					get_decision(&decision);
				}
			} else {
				g_printerr(
						"%s Backend picking rule didn't specify HIH, rejecting!\n",
						H(pkt->conn->id));
				decision.result = DE_REJECT;
			}
		} else {
			/* Check each backend, first to accept will take it */
			g_tree_foreach(pkt->conn->target->back_rules,
					(GTraverseFunc) get_decision_backend,
					(gpointer *) (&decision));
		}

		break;
	case CONTROL:
		/* If we're in CONTROL, we need to get the "limit" rule from the target */
		decision.node = (struct node *) pkt->conn->target->control_rule;
		get_decision(&decision);
		break;
	default:
		/* should never happen */
		g_printerr("%s Packet sent to DE with invalid state: %d\n",
				H(pkt->conn->id), pkt->conn->state);
		return statement;
		break;
	}

	switch (decision.result) {
	/* NULL rule (-2) */
	case DE_NO_RULE:
		switch (pkt->conn->state) {
		case CONTROL:
			/*! we update the state */
			//pkt->conn->state = PROXY;
			switch_state(pkt->conn, PROXY);
			/*! we release the packet */
			//send_raw(pkt->packet.ip);
			statement = 1;
			break;
		case INIT:
			if (g_tree_nnodes(pkt->conn->target->back_rules) == 0) {
				/*! no backend defined, so we simply forward the packets to its destination */
				//pkt->conn->state = PROXY;
				switch_state(pkt->conn, PROXY);
			} else {
				/*! backend defined, so we'll use the backend_rule for the next packet */
				//pkt->conn->state = DECISION;
				switch_state(pkt->conn, DECISION);
			}
			//send_raw(pkt->packet.ip);
			statement = 1;
			break;
		}
		break;
		/* Rule can't decide (yet) (-1) */
	case DE_UNKNOWN:
		g_printerr("%s Rule can't decide (yet)\n", H(pkt->conn->id));
		/*! we leave the state unmodified (the rule probably needs more material to decide), and we release the packet */
		//send_raw(pkt->packet.ip);
		statement = 1;
		break;
		/* Rule rejects (0) */
	case DE_REJECT:
		g_printerr("%s Rule decides to reject\n", H(pkt->conn->id));
		switch (pkt->conn->state) {
		case DECISION:
			//pkt->conn->state = PROXY;
			//send_raw(pkt->packet.ip);
			statement = 1;
			break;
		default:
			//pkt->conn->state = DROP;
			switch_state(pkt->conn, DROP);
			break;
		}
		break;
		/* Rule accepts (1) */
	case DE_ACCEPT:
		g_printerr("%s Rule decides to accept\n", H(pkt->conn->id));
		switch (pkt->conn->state) {
		case INIT:
			if (g_tree_nnodes(pkt->conn->target->back_handlers) == 0) {
				//pkt->conn->state = PROXY;
				printf("No back rules and back picker is null\n");
				switch_state(pkt->conn, PROXY);
			} else {
				//pkt->conn->state = DECISION;
				switch_state(pkt->conn, DECISION);
			}
			//send_raw(pkt->packet.ip);
			statement = 1;
			break;
		case DECISION:
			/*
			 #ifdef DEBUG
			 g_printerr("%s [** HIH address: %s (%d) **]\n", H(pkt->conn->id),
			 addr_ntoa(pkt->conn->target->back_handler),
			 pkt->conn->target->back_handler->addr_ip);
			 g_printerr("%s [** LIH address: %s (%d) **]\n", H(pkt->conn->id),
			 addr_ntoa(pkt->conn->target->front_handler),
			 pkt->conn->target->front_handler->addr_ip);
			 #endif
			 */
			g_printerr("%s Redirecting to HIH: %u\n", H(pkt->conn->id),
					decision.backend_use);
			if (setup_redirection(pkt->conn, decision.backend_use) != OK) {
				g_printerr("%s setup_redirection() failed\n", H(pkt->conn->id));
			}
			break;
		case CONTROL:
			//send_raw(pkt->packet.ip);
			statement = 1;
			break;
		}
		break;
	}

	return statement;
}

/*! DE_submit_packet DEPRECATED, \todo to remove
 \brief handle connections being decided and submits packets for decision
 */
void DE_submit_packet() {
	struct pkt_struct* pkt;

	while (threading == OK) {
		if (DE_queue == NULL) {
			g_usleep(1);
		} else {
			pkt = (struct pkt_struct*) g_slist_nth_data(DE_queue, 0);
			DE_process_packet(pkt);

			/*! Now that this entry was processed, we can remove it from the DE queue */
			g_static_rw_lock_writer_lock(&DE_queue_lock);
			DE_queue = g_slist_delete_link(DE_queue, DE_queue);
			g_static_rw_lock_writer_unlock(&DE_queue_lock);
		}
	}
}

/*! DE_push_pkt DEPRECATED, \todo to remove
 \brief push packet to the DE_submit_pkt queue (equivalent of DE_submit_packet() but without using a thread)
 \param[in] pkt: packet to push
 \return OK */
void DE_push_pkt(struct pkt_struct *pkt) {
	g_printerr("%s Pushing packet to DE (locking DE_queue_lock)\n",
			H(pkt->conn->id));
	g_static_rw_lock_writer_lock(&DE_queue_lock);
	DE_queue = g_slist_append(DE_queue, (gpointer*) pkt);
	g_static_rw_lock_writer_unlock(&DE_queue_lock);
	g_printerr("%s Packet pushed to DE (unlocked DE_queue_lock)\n",
			H(pkt->conn->id));
}

