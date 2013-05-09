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

#include <pcap.h>
#include <limits.h>

int daemon(int, int);

int yyparse(void);
extern FILE *yyin;

/*! writing lock initialization */
#define G_STATIC_RW_LOCK_INIT { G_STATIC_MUTEX_INIT, NULL, NULL, 0, FALSE, 0, 0 }

/*! Multi-thread safe mode */
#define G_THREADS_ENABLED

/*! Decision Engine thread enabled */
//#define DE_THREAD
/*! Two strategies: with thread or with libev 
 *  If HAVE_LIBEV is defined, the program loops on the main libev loop:
 *	- packets on queue are processed through libev callback
 *	- connection structures are cleaned by libev timer
 *  If not, then the program loops on nfqueue:
 *	- packets on queue are processed through nfqueue callback
 *	- connection structures are cleaned by a thread
 */
//#define HAVE_LIBEV
/*!
 \def DESTSIZE
 *
 * max size of an IP address (4*3 = 12 + 3 dots = 15) */
#define DESTSIZE 15

/*!
 \def CONF_MAX_LINE
 *
 * max size of a line in the configuration file */
#define CONF_MAX_LINE LINE_MAX

/*!
 \def BUFSIZE
 * use by NF_QUEUE to set the data size of received packets
 */
#define BUFSIZE         2048

/*!
 \def PAYLOADSIZE
 * use by NF_QUEUE to set the data size of received packets
 */
#define PAYLOADSIZE     0xffff

/*!
 \def running
 *
 * Init value: OK
 * Set to NOK when honeybrid stops
 * It is used to stop processing new data wht NF_QUEUE when honeybrid stops */
status_t running;

/*!
 \def thread_clean
 \def thread_log */
GThread *thread_clean;
GThread *thread_de;

#ifdef HAVE_LIBEV
#include <ev.h>
struct nfq_handle *h;
struct ev_loop *loop;
#endif
