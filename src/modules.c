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

#include "../config.h"
#include "modules.h"
#include "log.h"

/*! \todo create two functions to handle module backup to file:
 - a function called by modules to add themselves to a backup queue
 - a timer event callback function to process the backup queue periodically, and save backups to files
 */

/*! init_modules
 \brief setup modules that need to be initialized
 */
void init_modules() {
	g_printerr("%s Initiate modules\n", H(6));
	init_mod_hash();

#ifdef HAVE_XMPP
	init_mod_dionaea();
#endif

	init_mod_vmi();

	/*! create a thread that will save module memory every minute */
	module_to_save = g_hash_table_new(g_str_hash, g_str_equal);
	if (g_thread_create_full((void *) save_backup_handler, NULL, 0, FALSE, TRUE,
			G_THREAD_PRIORITY_LOW, NULL) == NULL) {
		errx(1, "%s Cannot create a thread to save module memory", H(6));
	}
}

/*! run_module
 * \brief test of a new function to run module based on module name (without calling get_module)
 */
void run_module(char *module_name, struct mod_args *args) {
	g_printerr("%s %s called\n", H(args->pkt->conn->id), module_name);

	if (g_strcmp0(module_name, "hash") == 0) {
		mod_hash(args);
	} else if (g_strcmp0(module_name, "source") == 0) {
		mod_source(args);
	} else if (g_strcmp0(module_name, "counter") == 0) {
		mod_counter(args);
	} else if (g_strcmp0(module_name, "control") == 0) {
		mod_control(args);
	} else if (g_strcmp0(module_name, "yesno") == 0) {
		mod_yesno(args);
	} else if (g_strcmp0(module_name, "random") == 0) {
		mod_random(args);
#ifdef HAVE_XMPP
	} else if (g_strcmp0(module_name, "dionaea") ==0) {
		mod_dionaea(args);
#endif
	} else if (g_strcmp0(module_name, "source_time") == 0) {
		mod_source_time(args);
	} else if (g_strcmp0(module_name, "backpick_random") == 0) {
		mod_backpick_random(args);
	} else if (g_strcmp0(module_name, "vmi") == 0) {
		mod_vmi(args);
	} else {
		g_printerr("%s module name invalid (%s)\n", H(args->pkt->conn->id),
				module_name);
		args->node->result = -1;
	}
}

/*! get_module
 \brief return the module function pointer from name
 \param[in] modname: module name
 \return function pointer to the module
 */
void (*get_module(char *modname))(struct mod_args *)
		{

			if (!strncmp(modname, "hash", 6))
				return mod_hash;
			else if (!strncmp(modname, "counter", 7))
				return mod_counter;
			else if (!strncmp(modname, "yesno", 5))
				return mod_yesno;
			else if (!strncmp(modname, "source", 6))
				return mod_source;
			else if (!strncmp(modname, "random", 6))
				return mod_random;
			else if (!strncmp(modname, "control", 6))
				return mod_control;
#ifdef HAVE_XMPP
			else if(!strncmp(modname,"dionaea",7))
			return mod_dionaea;
#endif
			else if (!strncmp(modname, "source_time", 11))
				return mod_source_time;
			else if (!strncmp(modname, "backpick_random", 16))
				return mod_backpick_random;
			else if (!strncmp(modname, "vmi", 3))
				return mod_vmi;

			errx(1, "%s No module could be found with the name: %s", H(6),
					modname);
		}

		/*! write_backup
		 *  \brief This function write a module backup memory to a file
		 */

		int write_backup(char *filename, GKeyFile *data, void *userdata) {
			g_printerr("%s saving backup module %p to %s\n", H(6), data,
					filename);
			gchar *buf;
			buf = g_key_file_to_data(data, NULL, NULL);

			FILE *file_fd;
			if (NULL == (file_fd = fopen(filename, (char *) "w+"))) {
				g_printerr(
						"%s Failed to save module backup \"%s\": can't open file for writing\n",
						H(0), filename);
				return FALSE;
			}
			fprintf(file_fd, "%s", buf);
			fclose(file_fd);
			g_free(buf);

			return TRUE;
		}

		/*! save_backup_handler
		 * \brief This function handles the automatic saving of modules to external files.
		 * It works by checking an array in which modules to save have been registered
		 * This array is updated after each module run
		 */
		void save_backup_handler() {
			int removed;
			while (threading == OK) {
				/*! saving module every 60 seconds */
				g_usleep(60000000);
				removed = g_hash_table_foreach_steal(module_to_save,
						(GHRFunc) write_backup, NULL);
				g_printerr(
						"%s %d entries saved and removed from module_to_save\n",
						H(0), removed);
			}

			if (threading != OK) {
				g_hash_table_destroy(module_to_save);
			}

		}

		/*! save_backup
		 *  \brief This function adds a module backup memory to a queue in order to be written to a file later
		 */
		int save_backup(GKeyFile *data, char *filename) {
			g_printerr("%s called for %p (%s)\n", H(0), data, filename);
			if (FALSE
					== g_hash_table_lookup_extended(module_to_save, filename,
							NULL, NULL)) {
				g_printerr("%s adding a new entry in module_to_save\n", H(0));
				g_hash_table_insert(module_to_save, filename, data);
				return 1;
			} else {
				g_hash_table_replace(module_to_save, filename, data);
				g_printerr(
						"%s module_to_save already had this entry, updated\n",
						H(0));
				return 0;
			}
		}

//	int len;
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
