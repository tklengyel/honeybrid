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

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include "types.h"

/*! \brief the pid of the main program
 */
long int mainpid;

const char *pidfile;

/*!
 \def threading
 * Init value: OK
 * Set to NOK when honeybrid stops, used to terminate threads
 *
 */
status_t threading;

/*!
 \def threading_cond_lock
 \def thread_cond
 *
 * Conditional to signal threads that may be asleep that they need to exit.
 */
GMutex threading_cond_lock;
GCond threading_cond;

/*! \brief connection id */
uint64_t c_id;

/*! \brief max number of packets to save for replay in an EXT<->LIH connection (negative value = save all) */
uint64_t max_packet_buffer;

int deny_hih_init;

int reset_ext;

int exclusive_hih;

uint32_t target_counter;

/*! \brief global array of pointers to hold target structures */
GTree *targets;

/*! \brief global hash table that contain the values of the configuration file  */
GHashTable *config;

/*! \brief global hash table to hold module paramaters */
GHashTable *module;

/*! \brief global hash table to hold module paramaters */
GHashTable *links;

// Our connection tracking is quite complex, but it is required to support
// some exotic setups with clone routing, internal targets, VLANs, etc..

// NEW: Protocol:externalSrcIP:externalSrcPort:targetDstIP:targetDstPort -> conn_struct
GTree *ext_tree1;
// REPLY: Protocol:internalSrcIP:internalSrcPort:externalDstIP:externalDstPort:VLAN -> conn_struct
GTree *ext_tree2;
// NEW: Protocol:internalSrcIP:internalSrcPort:externalDstIP:externalDstPort:VLAN -> conn_struct
GTree *int_tree1;
// REPLY: Protocol:externalSrcIP:externalSrcPort:targetDstIP:targetDstPort -> conn_struct
GTree *int_tree2;
// Map VLAN:internalSrcIP:externalDstIP -> targetDstIP
GTree *comm_pin_tree;
// Map VLAN:internalSrcIP -> targetDstIP
GTree *target_pin_tree;
// NEW: Protocol:internalSrcIP:internalSrcPort:targetDstIP:targetDstPort:VLAN -> conn_struct
GTree *intra_tree1;
// REPLY: Protocol:intraSrcIP:intraSrcPort:internalSrcIP:internalSrcPort:VLAN -> conn_struct
GTree *intra_tree2;
// Map VLAN:intraSrcIP:internalDstIP -> targetDstIP
GTree *intra_pin_tree;

/*! \brief security writing lock for the Binary Trees
 */
GMutex connlock;

/*! \brief security writing lock for the target table
 */
GRWLock targetlock;

/*! \def list of module to save
 */
GHashTable *module_to_save;

/*! \brief pointer table for btree cleaning */
GPtrArray *entrytoclean;

/*!
 \def thread_clean
 \def thread_log */
GThread *thread_clean;
GThread *mod_backup;

/*!
 \def decision_threads
 \def de_threads
 \def de_queues
 *
 * Asynchronous multi-threaded packet processing
 * Each de_thread has it's own queue to which packet's are being pushed
 * based on their source and destination address so that each attack session will
 * be handled by the same thread.
 * This ensures that packets belonging to the same connection are processed in FIFO order.
 * */
uint32_t decision_threads;
GThread **de_threads;
GAsyncQueue **de_queues;

/*!
 \def log level
 */

log_verbosity_t LOG_LEVEL;

/*!
 \def log printing header lock
 */
GMutex log_header_lock;

char log_header_string[200];

/*!
 \Def enable/disable debug output
 */
gboolean debug;

/*!
 \Def file descriptor to log debug output
 */
int fdebug;

/*!
 \Def broadcast
 */
gboolean broadcast_allowed;
struct addr broadcast;

#endif //__GLOBALS_H__
