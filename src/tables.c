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

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include "tables.h"
#include "log.h"
#include "netcode.h"
#include "decision_engine.h"

/*! config_lookup
 /brief lookup values from the config hash table. Make sure the required value is present
 */

gpointer config_lookup(char * parameter, gboolean required) {
	gpointer ret = g_hash_table_lookup(config, parameter);
	if (!ret && required) {
		errx(1, "Missing configuration parameter '%s'", parameter);
	}
	return ret;
}

gint intcmp(gconstpointer v1, gconstpointer v2, gconstpointer v3) {
	return (*(uint32_t *) v1 < (*(uint32_t *) v2) ? 1 :
			(*(uint32_t *) v1 == (*(uint32_t *) v2)) ? 0 : -1);
}

void free_interface(gpointer data) {
	struct interface *iface = (struct interface *) data;
	if (iface) {
		g_free(iface->ip);
		g_free(iface->ip_str);
		g_free(iface->name);
		g_free(iface->tag);
		g_free(iface);
	}
}

void free_backend(gpointer data) {
	struct backend *backend = (struct backend *) data;

	if (backend) {
		DE_destroy_tree(backend->rule);
		free_interface(backend->iface);
		g_free(backend);
	}
}
