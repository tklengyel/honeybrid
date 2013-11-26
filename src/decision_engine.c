/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
 * (Extended by Tamas K Lengyel <tamas.k.lengyel@gmail.com>
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

#include "decision_engine.h"
#include "modules.h"
#include "connections.h"
#include "log.h"
#include "globals.h"
#include "structs.h"
#include "constants.h"

/*! build_subtree
 \param[in] expr, a part of the boolean equation
 *
 \brief recursively process the expression and creates the nodes */
struct node *DE_build_subtree(const gchar *expr) {
	struct node *node;
	node = (struct node *) g_malloc0(sizeof(struct node));
	node->module = NULL;
	char *modname;
	const char *function;
	module_function function_pointer;

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
		node->true_branch = DE_build_subtree(and[1]);
		node->false_branch = NULL;
	} else {
		/*! single module in expression, just add the leaf */

#ifdef DEBUG
		g_print("\t\tNo operator found in '%s'\n", expr);
#endif

		modname = g_strdup(expr);
		node->true_branch = NULL;
		node->false_branch = NULL;
	}

	/*! get module structure from DE_rules
	 */
	if ((node->config = (GHashTable *) g_hash_table_lookup(module, modname))
			== NULL) {
		errx(1, "%s: Module '%s' unknown!", __func__, modname);
	}
	if ((function = (const char *) g_hash_table_lookup(node->config, "function"))
			== NULL) {
		errx(1, "%s: Module function undefined!", __func__);
	}
	if ((function_pointer = get_module(function)) == NULL) {
		errx(1, "%s: Module function pointer undefined!", __func__);
	}

	node->module = function_pointer;
	node->module_name = g_string_new(NULL);
	node->function = g_string_new(NULL);
	g_string_printf(node->module_name, "%s", modname);
	g_string_printf(node->function, "%s", function);

	printdbg("\t\tModule function '%s' defined\n", function);

	g_regex_unref(and_regex);
	g_free(modname);

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

	struct node *node = DE_build_subtree(subgroups[0]);

	/*! for all the other subgroups */
	int n = 1;
	for (n = 1; subgroups[n] != NULL; n++) {
		printdbg("\t\tAnalyzing subgroup %i: '%s'\n", n, subgroups[n]);

		/*! get the pointer to the beginning of the new subtree */
		struct node *headsubgroup;
		headsubgroup = DE_build_subtree(subgroups[n]);

		/*! connect new subtree to the previous one
		 * subtree (n) is a son of subtree(n-1) */
		node->false_branch = headsubgroup;

		while (node->true_branch != NULL) {
			/*! and go to the next one */
			if (node->true_branch != NULL)
				node = node->true_branch;

			/*! in subtree (n-1), each FALSE branch is
			 * connected to the head of subtree(n) */
			node->false_branch = headsubgroup;

		}

		/*! this subtree is done, so n become n-1 */
		node = headsubgroup;
	}
	g_strfreev(subgroups);
	g_regex_unref(or_regex);
	or_regex = NULL;

	return node;

}

/*! DE_destroy_tree
 \brief destroy a boolean decision tree
 *
 \param[in] root node
 */
void DE_destroy_tree(struct node *clean) {
	if (clean != NULL) {
		DE_destroy_tree(clean->false_branch);
		DE_destroy_tree(clean->true_branch);
		if (clean->module_name)
			g_string_free(clean->module_name, TRUE);
		if (clean->function)
			g_string_free(clean->function, TRUE);
		g_free(clean);
	}
}

/*! decide
 \brief decide upon a given paken if the connection is to be redirected or not
 \param[in] pkt: packet used to decide
 \param[in] hih_search: which HIH are we testing (if it's a HIH, -1 otherwise)
 \return decision
 */

void decide(struct decision_holder *decision) {

	struct mod_args args = { .pkt = decision->pkt, .backend_test =
			decision->backend_test, .backend_use = 0 };

	struct node *node = decision->node;
	decision->result = DE_DEFER;

	/*! start processing the tree from the root */
	while (1) {

		printdbg(
				"%s >> Calling module %s at address %p\n", H(decision->pkt->conn->id), node->module_name->str, node->module);

		mod_result_t result;
		args.node = node;

		run_module(node->module, &args, result);

		printdbg(
				"%s >> Done, result is %s\n", H(decision->pkt->conn->id), lookup_result(result));

		switch (result) {
		case ACCEPT:
			/*! if result is true, forward to true node or exit with 1 */
			/*! update decision_rule information */

			/* Global multi-hih module that tells which HIH ID to use */
			if (args.backend_use != 0) {
				printdbg(
						"%s >> Module suggested using HIH %lu\n", H(decision->pkt->conn->id), args.backend_use);
				decision->backend_use = args.backend_use;
			}

			if (node->true_branch != NULL) {
				/*! go to next node */
				node = node->true_branch;
			} else {
				decision->result = DE_ACCEPT;
				/*! end of the tree, exit */
				goto done;
			}
			break;
		case DEFER:
			decision->result = DE_DEFER;
			goto done;
			break;
		case REJECT:
		default:

			if (node->false_branch != NULL) {
				/*! go to next node */
				node = node->false_branch;
			} else {
				decision->result = DE_REJECT;
				/*! end of the tree, exit */
				goto done;
				break;
			}

			break;
		}
	}

	done: return;
}

static inline
void get_decision(struct decision_holder *decision) {
	if (decision->node == NULL) {
		printdbg(
				"%s rule is NULL for state %s on target %p\n", H(decision->pkt->conn->id), lookup_state(decision->pkt->conn->state), decision->pkt->conn->target);
	} else {
		printdbg(
				"%s Rule available, deciding...\n", H(decision->pkt->conn->id));
		decide(decision);
		decision->pkt->conn->decision_packet_id =
				decision->pkt->conn->total_packet;
	}
}

int get_decision_backend(uint32_t *key, struct handler * back_handler,
		struct decision_holder * decision) {
	decision->backend_test = *key;
	decision->node = back_handler->rule;
	get_decision(decision);

	/* Stop searching on the first accept */
	if (decision->result == DE_ACCEPT) {
		decision->backend_use = *key;
		return TRUE;
	} else {
		return FALSE;
	}
}

/*! DE_process_packet
 \brief submit packets for decision using decision rules and decision modules
 returns OK if the packet should be accepted, NOK in the case the packet should be dropped */
status_t DE_process_packet(struct pkt_struct *pkt) {

	/* This structure holds the result of LIH/HIH/CONTROL equations */
	/* The flow is get_decision->decide->run_module */
	/* For multi-HIH backends a module can set the backend_use variable in the mod_args structure to give the HIH ID */
	/* Otherwise each HIH backend can be checked one-by-one */

	struct decision_holder decision = { .pkt = pkt, .result = DE_NO_RULE,
			.backend_test = 0, .backend_use = 0 };

	status_t result = NOK;

	printdbg("%s Packet pushed to DE: %"PRIx32"\n", H(pkt->conn->id), pkt->packet.ip->saddr);

	switch (pkt->conn->state) {
	case INIT:
		decision.node = pkt->conn->target->front_handler->rule;
		get_decision(&decision);

		/* If we're in INIT, we need to get ACCEPT or REJECT from the frontend definition of the target */
		if (decision.result == DE_DEFER) {
			decision.result = DE_REJECT;
		}

		break;
	case DECISION:

		/* Check if global rule for multi-hih available */
		if (pkt->conn->target->back_picker != NULL) {
			decision.node = pkt->conn->target->back_picker;
			get_decision(&decision);

			if (decision.result == DE_ACCEPT && decision.backend_use != 0) {
				// Back picker gave us a HIH, run it's test (if any)
				printdbg(
						"%s Global backend rule gave us a HIH: %lu\n", H(pkt->conn->id), decision.backend_use);

				struct handler *back_handler = (struct handler *) g_tree_lookup(
						pkt->conn->target->back_handlers,
						&(decision.backend_use));

				if (back_handler->rule) {
					decision.node = back_handler->rule;
					get_decision(&decision);
				}
			} else {
				printdbg(
						"%s Backend picking rule didn't specify HIH, rejecting!\n", H(pkt->conn->id));
			}
		} else {
			/* Check each backend, first to accept will take it */
			g_tree_foreach(pkt->conn->target->back_handlers,
					(GTraverseFunc) get_decision_backend,
					(gpointer *) (&decision));
		}

		break;
	case CONTROL:
		if (pkt->conn->destination == EXT) {
			decision.node = pkt->conn->target->control_rule;
			get_decision(&decision);
		} else if (pkt->conn->destination == INTRA) {

			// If the connection has a handler assigned, use its rule
			// otherwise take the rule from the target
			decision.node =
					pkt->conn->intra_handler ?
							pkt->conn->intra_handler->rule :
							pkt->conn->target->intra_rule;
			get_decision(&decision);

			/* We need to get ACCEPT or REJECT from the intra rule */
			if (decision.result == DE_DEFER || decision.result == DE_NO_RULE) {
				decision.result = DE_DROP;
			}
		}
		break;
	default:
		/* should never happen */
		printdbg(
				"%s Packet sent to DE with invalid state: %d\n", H(pkt->conn->id), pkt->conn->state);
		break;
	}

	switch (decision.result) {
	case DE_NO_RULE:
		switch (pkt->conn->state) {
		case CONTROL:
			/*! we update the state */
			switch_state(pkt->conn, PROXY);
			break;
		case INIT:
			if (pkt->conn->target->back_handler_count == 0) {
				/*! no backend defined, so we simply forward the packets to its destination */
				switch_state(pkt->conn, PROXY);
			} else {
				/*! backend defined, so we'll use the backend_rule for the next packet */
				switch_state(pkt->conn, DECISION);
			}
			break;
		default:
			break;
		}

		result = OK;
		break;
	case DE_DEFER:
		/* Rule can't decide (yet) */
		printdbg("%s Rule can't decide (yet)\n", H(pkt->conn->id));
		/*! we leave the state unmodified (the rule probably needs more material to decide), and we release the packet */
		result = OK;
		break;
	case DE_ACCEPT:
		printdbg("%s Rule decides to accept\n", H(pkt->conn->id));
		switch (pkt->conn->state) {
		case INIT:
			if (pkt->conn->target->back_handler_count == 0
					&& !pkt->conn->target->back_picker) {
				printdbg(
						"%s No back rules and back picker is null\n", H(pkt->conn->id));
				switch_state(pkt->conn, PROXY);
			} else {
				switch_state(pkt->conn, DECISION);
			}
			result = OK;
			break;
		case DECISION:
			printdbg(
					"%s Redirecting to HIH: %lu\n", H(pkt->conn->id), decision.backend_use);
			if (NOK == setup_redirection(pkt->conn, decision.backend_use)) {
				printdbg(
						"%s setup_redirection() failed\n", H(pkt->conn->id));
			}
			break;
		case CONTROL:
			result = OK;
			break;
		default:
			break;
		}
		break;
	case DE_REJECT:
		printdbg("%s Rule decides to reject\n", H(pkt->conn->id));
		switch (pkt->conn->state) {
		case DECISION:
			// The HIH rejected the packet so we keep it on the LIH
			switch_state(pkt->conn, PROXY);
			break;
		default:
			switch_state(pkt->conn, DROP);
			break;
		}
		break;
	case DE_DROP:
		printdbg("%s Rule decides to drop\n", H(pkt->conn->id));
		switch_state(pkt->conn, DROP);
		break;
	}

	return result;
}
