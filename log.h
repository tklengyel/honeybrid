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

/*
 * id values
 1 -> main
 2 -> signal handlers
 3 -> config parse
 4 -> unkown connection
 5 -> pcap tools
 6 -> modules
 7 -> 
 8 -> clean engine
 9 -> honeypot queries
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <glib.h>

/*!
 \def log_list
 *
 \brief global singly linked list that contain the log entries to write
 */
GSList *log_list;


/*!
\def loglock
\brief security writing lock for the lgo singly linked list
 */
GStaticRWLock loglock;

struct log_event
{
	char *sdata;
	char *ddata;
	int level;
	unsigned id;
	char *curtime;
};
/*!
 \def error_table
 *
 \brief global hash table that contain the error values and their descriptions
 */
GHashTable *log_table;

#define L(sdata,ddata,level,id) if (0 != honeylog(sdata,ddata,level,id)){g_print("******LOG ENGINE ERROR******\n");}

int honeylog(char *sdata, char *ddata, int level, unsigned id);

void write_log();

#endif ///_LOG_H_

