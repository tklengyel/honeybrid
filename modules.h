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

//#ifndef _NO_SSL_
#include <openssl/evp.h>
//#endif

#include "log.h"
#include "tables.h"

/*!
 \def mod_args
 *
 \brief arguments sent to a module while processing the tree
 */
struct mod_args
{
	struct node *node;
	struct pkt_struct *pkt;
};


/*!
 \def node
 *
 \brief node of an execution tree, composed of a module and a argument, called by processing the tree
 */
struct node
{
	void (*module)(struct mod_args);
	char *arg;
	GString *module_name;
	struct node *true;
	struct node *false;
	int result;
	int info_result;
};


void mod_table_init();

void (*get_module(char *modname))(struct mod_args);

/*!*************** YESNO FUNCTIONS AND VARIABLES ***********************************************/

/*! mod_yesno
 \brief replies as asked 
 */
void mod_yesno(struct mod_args args);


/*!*************** PACKET POSITION COUNTER FUNCTIONS AND VARIABLES *****************************/

/*! mod_incpsh
 \brief count push packets from the attacker
 */
void mod_incpsh(struct mod_args args);


/*!*************** SHA-1 FUNCTIONS AND VARIABLES ***********************************************/


//#ifndef _NO_SSL_
/*! message digest function
 */
const EVP_MD *md;
//#endif

/*!
 \def SHA1 BDD HASH TABLES
 */
GHashTable **sha1_bdd;

int init_mod_sha1();

void mod_sha1(struct mod_args args);

/*!
 \def Source bdd hash table
 */
GHashTable **source_bdd;

int init_mod_source();

void mod_source(struct mod_args args);

/*! module RANDOM
 */

int init_mod_random();

void mod_random(struct mod_args args);

/*! module PROXY
 */
void mod_proxy(struct mod_args args);

#endif //_MODULES_H_
