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

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "modules.h"
#include "log.h"

/*! \todo create two functions to handle module backup to file:
	- a function called by modules to add themselves to a backup queue
 	- a timer event callback function to process the backup queue periodically, and save backups to files
*/

/*! init_modules
 \brief setup modules that need to be initialized
*/
void init_modules()
{
	g_printerr("%s Initiate modules\n", H(6));
	init_mod_hash();
}

/*! get_module
 \brief return the module function pointer from name
 \param[in] modname: module name
 \return function pointer to the module
 */
void (*get_module(char *modname))(struct mod_args)
{
	
	     if(!strncmp(modname,"hash",6))
		return mod_hash;
	else if(!strncmp(modname,"counter",7))
		return mod_counter;
	else if(!strncmp(modname,"yesno",5))
		return mod_yesno;
	else if(!strncmp(modname,"source",6))
		return mod_source;
	else if(!strncmp(modname,"random",6))
		return mod_random;

	errx(1, "%s No module could be found with the name: %s", H(6), modname);
}

/*! save_backup
 *  \brief This function save a module backup memory to a file
 */

int save_backup(GKeyFile *data, char *filename) {
	gchar *buf;
//	int len;

	buf = g_key_file_to_data(data, NULL, NULL);	

//	g_printerr("%s Preparing to write:\n%s\n", H(0), buf);
	
	/*
	GError *error = NULL;
	if (!g_file_set_contents(filename, buf, len, &error)) {
		if (error) {
			g_printerr("%s Failed to save module backup \"%s\": %s\n", H(0), filename, error->message);
			g_error_free(error);
		} else {
			g_printerr("%s Failed to save module backup \"%s\";\n", H(0), filename);
		}
		g_free(buf);
		return NOK;
	}
	g_free(buf);
	return OK;
	*/
	/*
	int fd;
	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
		S_IRUSR | S_IWUSR);
	if (fd < 0) {
		g_printerr("%s Failed to save module backup \"%s\": can't open file for writing\n", H(0), filename);
		g_free(buf);
		return NOK;
	}

	if (write(fd, buf, len) < (gssize) len) {
		g_printerr("%s Failed to save module backup \"%s\": can't write to file\n", H(0), filename);
		close(fd);
		g_free(buf);
		return NOK;
	}
	close(fd);
	g_free(buf);
	return OK;
	*/


	FILE *file_fd;
	if (NULL == (file_fd = fopen(filename, (char *) "w+"))) {
		g_printerr("%s Failed to save module backup \"%s\": can't open file for writing\n", H(0), filename);
        }
	fprintf(file_fd, "%s", buf);
	fclose(file_fd);
	g_free(buf);
        return OK;

}

