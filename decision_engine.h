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

#ifndef __DECISION_ENGINE_H__
#define __DECISION_ENGINE_H__

#include <glib.h>
#include "tables.h"

/*!
 \def DE_pool
 *
 \brief the global pointer to the decision engine pool of threads
 */
GThreadPool *DE_pool;

/*!
 \def redirection_table
 *
 \brief global hash table that contain the correspondance between LIH services et HIH services
 */
GHashTable *DE_mod;


/*!
 \def DE_rules
 *
 \brief hash table to select a rule for a connection, key is the rule, value is the boolean decision tree root
 */
GHashTable *DE_rules;

/*!
 \def tree
 *
 \brief a binary execution tree
 */
struct tree
{
	struct node *node;
	int globalresult;
	GStaticRWLock lock;
};

struct tree tree;

GStaticRWLock DE_queue_lock;

GSList *DE_queue;

void *DE_create_tree(const gchar *equation);

void DE_submit_packet();

int DE_push_pkt(struct pkt_struct *pkt);

#endif
