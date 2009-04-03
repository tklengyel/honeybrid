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

/*! \file random_mod.c
 * \brief RANDOM module for honeybrid Decision Engine
 *
 * This module is called by a boolean decision tree to filter attacker randomly
 * using a probability given as an argument
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

#include "random_mod.h"

/*! init_mod_random
 \brief init the random module, fill up the databases */
int init_mod_random()
{
	L("init_mod_random():\tInitializing Random Module\n",NULL,3,6);
	return 0;
}

/*! mod_random
 \param[in] args, struct that contain the node and the data to process
 \param[in] user_data, not used
 *
 \param[out] set result to 0 if attacker ip is found in search table, 1 if not
 */
void mod_random(struct mod_args args)
{
	L("mod_random():\tModule called\n", NULL, 3, args.pkt->connection_data->id);

	unsigned int value;
	unsigned int proba;
	int selector = 1;
	char *logbuf;
	char *type;
	int drop, check;

	/*! by defaut we discard
	 */
	args.node->result = 0; 
	
	/*! getting the value provided in argument
	 */
	//sscanf(args.node->arg,"%d",&value);
	type = malloc(64);
        check = sscanf(args.node->arg,"%d,%s", &value, type);

        if (check != 2) {
                L("mod_random():\tError: module argument malformed!\n", NULL, 3, args.pkt->connection_data->id);
                return;
        }

        if (strcmp( type, "drop") == 0) {
                drop = -1;
        } else {
                drop = 0;
        }
	free(type);

	if (value < selector) {
		logbuf = malloc(256);
		sprintf(logbuf, "mod_random():\tIncorrect value given in argument: %d\n", value);
		L(NULL, logbuf, 3, args.pkt->connection_data->id);
		return;
	}

	/*! deciding based on a probability of 1 out of "value":
	 */
	proba = (int) (((double)value) * (rand() / (RAND_MAX + 1.0)));	

	if (proba == selector) {
		args.node->result = 1;
		logbuf = malloc(256);
                sprintf(logbuf,"mod_random():\tPACKET MATCH RULE for random(%d)\n", value);
                L(NULL, logbuf, 2, args.pkt->connection_data->id);
	} else {
		args.node->result = drop;
		logbuf = malloc(256);
                sprintf(logbuf,"mod_random():\tPACKET DOES NOT MATCH RULE for random(%d)\n", value);
                L(NULL, logbuf, 2, args.pkt->connection_data->id);
	}

	return;
}

