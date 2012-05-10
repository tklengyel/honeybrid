/*
 * This file is part of the honeybrid project.
 *
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

/*! \file mod_backpic_random.c
 * \brief BACKPICK RANDOM module for honeybrid Decision Engine
 *
 \author Tamas K Lengyel 2012
 */

#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "tables.h"
#include "modules.h"
#include "netcode.h"

struct picking {
	int num;
	int counter;
	char *name;
};

int get_backpick(gpointer *key, gpointer *value, gpointer *data) {
	struct picking *pick = (struct picking *)data;
	if(pick->num==pick->counter) {
		pick->name = (char *)key;
		return 1;
	} else {
		pick->counter++;
		return 0;
	}
}

/*! mod_backpick_random
 \param[in] args, struct that contain the node and the data to process
 */
void mod_backpick_random(struct mod_args *args)
{
	g_printerr("%s Random backpick module called\n", H(args->pkt->conn->id));
	int n_backends = 0;

	if((n_backends=g_tree_nnodes(args->pkt->conn->target->back_handlers)) <= 0) {
		g_printerr("%s No backends are defined for this target, rejecting\n", H(args->pkt->conn->id));
		args->node->result = 0;
	} else {
		struct picking pick;
		pick.num = rand() % n_backends;
		pick.num=0;
		pick.counter=0;
		
		/* get the IP of the backend to use from the GTree */
		g_tree_foreach(args->pkt->conn->target->back_handlers, (GTraverseFunc)get_backpick, (gpointer *)(&pick));
		g_printerr("%s Picking %d: %s out of %d backends\n", H(args->pkt->conn->id), pick.num+1, pick.name, n_backends);
		args->backend_use=pick.name;
		args->node->result = 1;
	}
}

