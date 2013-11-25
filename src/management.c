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

#include "management.h"
#include "globals.h"
#include "convenience.h"

status_t add_target(struct target *target) {
	status_t ret = NOK;

	if (!target)
		goto done;

	g_rw_lock_writer_lock(&targetlock);
	target->targetID = target_counter++;
	if (!g_tree_lookup(targets, &target->targetID)) {

		g_mutex_init(&target->lock);

		if (!target->back_handlers)
			target->back_handlers = g_tree_new_full((GCompareDataFunc) intcmp,
					NULL, g_free, (GDestroyNotify) free_handler);

		if (!target->intra_handlers)
			target->intra_handlers = g_tree_new_full((GCompareDataFunc) intcmp,
					NULL, g_free, NULL);

		g_tree_insert(targets, &target->targetID, target);

		ret = OK;
	}
	g_rw_lock_writer_unlock(&targetlock);

	done: return ret;
}

status_t remove_target(uint32_t targetID) {
	status_t ret = NOK;

	g_rw_lock_writer_lock(&targetlock);
	struct target *target = g_tree_lookup(targets, &targetID);
	if (target && g_tree_remove(targets, &targetID)) {
		free_target(target);
		ret = OK;
	}
	g_rw_lock_writer_unlock(&targetlock);

	return ret;
}

status_t add_intra_handler(struct target *target, struct addr *target_ip,
		struct handler *handler) {
	status_t ret = NOK;

	if (!target || !handler)
		goto done;

	if (!handler->iface || !handler->ip || !handler->mac)
		goto done;

	g_mutex_lock(&target->lock);
	if (!g_tree_lookup(target->intra_handlers, target_ip)) {
		handler->intra_target_ips = g_slist_append(handler->intra_target_ips,
				target_ip);
		g_tree_insert(target->intra_handlers, target_ip, handler);
		ret = OK;
	}
	g_mutex_unlock(&target->lock);

	done: return ret;
}

status_t remove_intra_handler(struct target *target, struct handler *intra) {
	status_t ret = NOK;

	g_mutex_lock(&target->lock);
	GSList *loop = intra->intra_target_ips;
	while (loop) {
		g_tree_remove(target->intra_handlers, loop->data);
		loop = loop->next;
	}
	g_mutex_unlock(&target->lock);

	free_handler(intra);

	return ret;
}

status_t switch_to_intra(struct conn_struct *conn,
		struct handler *intra_handler) {

	conn->intra_handler = intra_handler;

	conn->intra_key = g_malloc0(sizeof(struct conn_key));
	conn->intra_key->protocol = conn->protocol;
	conn->intra_key->vlan_id = conn->intra_handler->vlan.vid;
	conn->intra_key->src_ip = conn->intra_handler->ip->addr_ip;
	conn->intra_key->src_port = conn->first_pkt_dst_port;
	conn->intra_key->dst_ip = conn->first_pkt_src_ip.addr_ip;
	conn->intra_key->dst_port = conn->first_pkt_src_port;

	g_mutex_lock(&connlock);

	// First remove this connection from the int_trees
	g_tree_remove(int_tree1, conn->int_key);
	g_tree_remove(int_tree2, conn->ext_key);

	// And reinsert it into the intra_trees
	g_tree_insert(intra_tree1, conn->int_key, conn);
	g_tree_insert(intra_tree2, conn->intra_key, conn);

	g_mutex_unlock(&connlock);

	return OK;
}
