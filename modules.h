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

#ifndef _MODULES_H_
#define _MODULES_H_

#include <glib.h>
#include <openssl/evp.h>

#include "log.h"
#include "tables.h"


/*!
 \def DE_mod
 *
 \brief hash table that contain the pointers to the modules pools of threads
 */
GHashTable *DE_mod;

/*!
 \def mod
 *
 \brief structure of a module (like sha1, expr, pos, ...)
 */
struct mod
{
	char *name;
	GThreadPool *pool;
};


/*!
 \def pool_args
 *
 \brief arguments sent to a module while processing the tree
 */
struct mod_pool_args
{
	struct node *node;
	struct pkt_struct *pkt;
	gpointer *ptr_to_poolargs;
};


/*!
 \def node
 *
 \brief node of an execution tree, composed of a module and a argument, called by processing the tree
 */
struct node
{
	void (*module)(struct mod_pool_args);
	char *arg;
	struct node *true;
	struct node *false;
	int result;

};


void mod_table_init();

void (*get_module(char *modname))(struct mod_pool_args);

/*!*************** YESNO FUNCTIONS AND VARIABLES ***********************************************/

/*! mod_yesno
 \brief replies as asked 
 */
void mod_yesno(struct mod_pool_args args);


/*!*************** PACKET POSITION COUNTER FUNCTIONS AND VARIABLES *****************************/

/*! mod_incpsh
 \brief count push packets from the attacker
 */
void mod_incpsh(struct mod_pool_args args);


/*!*************** SHA-1 FUNCTIONS AND VARIABLES ***********************************************/


/*! message digest function
 */
const EVP_MD *md;

/*!
 \def SHA1 BDD HASH TABLES
 */
GHashTable **bdd;

int init_mod_sha1();

void mod_sha1(struct mod_pool_args args);


#endif //_MODULES_H_
