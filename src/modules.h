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
	GHashTable *arg;
	GString *module_name;
	GString *function;
	struct node *true;
	struct node *false;
	int result;
	int info_result;
};

/*! \def list of module to save
 */
GHashTable *module_to_save;


void init_modules();

void run_module(char *module_name, struct mod_args args);

void (*get_module(char *modname))(struct mod_args);

void save_backup_handler();

int save_backup(GKeyFile *data, char *filename);

int write_backup(char *filename, GKeyFile *data, void *userdata);

/*!************ [Basic Modules] **************/

/*!** MODULE YESNO **/
void mod_yesno(struct mod_args args);

/*!** MODULE COUNTER **/
void mod_counter(struct mod_args args);

/*!** MODULE RANDOM **/
void mod_random(struct mod_args args);

/*!*********** [Advanced Modules] ************/

/*!** MODULE HASH **/
const EVP_MD *md;
int init_mod_hash();
void mod_hash(struct mod_args args);

/*!** MODULE SOURCE **/
void mod_source(struct mod_args args);

/*!** MODULE CONTROL **/
void mod_control(struct mod_args args);
//int control(struct pkt_struct *pkt);

#endif //_MODULES_H_
