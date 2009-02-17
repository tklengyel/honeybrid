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

/*! \file incpsh_mod.c
 * \brief Packet counter Module for honeybrid Decision Engine
 *
 * This module returns the position of a packet in the connection
 *
 *
 \author Julien Vehent, 2007
 \author Thomas Coquelin, 2008
 */

#include <string.h>

#include "modules.h"
#include "log.h"

/*! mod_table_init
 \brief init a module and store the pointer to the function in the DE_mod hash table
 */

void mod_table_init()
{
	L("DE_init_pool(): Initiate module\n",NULL, 2, 6);
	/*! init sha module
	 */
	init_mod_sha1();
}


/*! get_module
 \brief return the module function pointer from name
 \param[in] modname: module name
 \return function pointer to the module
 */
void (*get_module(char *modname))(struct mod_pool_args)
{
	if(!strncmp(modname,"sha1",6))
		return mod_sha1;
	else if(!strncmp(modname,"incpsh",6))
		return mod_incpsh;
	else if(!strncmp(modname,"yesno",6))
		return mod_yesno;
	return NULL;
}

