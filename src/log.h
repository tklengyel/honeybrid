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

#ifndef _LOG_H_
#define _LOG_H_

#include <glib.h>

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif

/*! 
 \def verbosity channel
 1 errors only
 2 minimal redirection information
 3 full redirection information
 4 internal processing events
 5 permanent internal processing events
 */
typedef enum {
	LOG_MIN = 1,
	LOG_LOW = 2,
	LOG_MED = 3,
	LOG_HIGH = 4,
	LOG_ALL = 5
} log_verbosity_t;

/*!
 \def log level
 */

log_verbosity_t LOG_LEVEL;

/*!
 \def log identifiers
 * log id values:
 1 -> main
 2 -> signal handlers
 3 -> config parse
 4 -> unkown connection
 5 -> pcap tools
 6 -> modules
 7 -> log
 8 -> clean engine
 9 -> honeypot queries
 */
typedef enum {
	LOG_MISC,
	LOG_MAIN,
	LOG_SIGNAL,
	LOG_CONFIG,
	LOG_UNKNOWN,
	LOG_PCAP,
	LOG_MODULES,
	LOG_LOG,
	LOG_CLEAN,
	LOG_HONEYPOT
} log_id_t;

/*!
 \Def file descriptor to log debug output
 */
int fdebug;

/*!
 \def log_list
 \brief global singly linked list that contain the log entries to write
 */
GSList *log_list;

/*!
 \def loglock
 \brief security writing lock for the lgo singly linked list
 */
GStaticRWLock loglock;

struct log_event {
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

#define L(sdata,ddata,level,id) 	if (0 != honeylog(sdata,ddata,level,id)){g_print("******LOG ENGINE ERROR******\n");}
#define H(id) 				log_header(__func__, id)

char* log_header(const char* function_name, int id);
char* now(void);

int honeylog(char *sdata, char *ddata, int level, unsigned id);

int open_debug_log(void);

int close_connection_log(void);

void open_connection_log(void);

//void rotate_log(int signal_nb, void *siginfo, void *context);
void rotate_connection_log(int signal_nb);

//void connection_stat(struct conn_struct *conn);
void connection_log();

#ifdef HAVE_MYSQL
MYSQL *mysqlConn;
int init_mysql_log();
#endif

#endif ///_LOG_H_
