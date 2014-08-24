/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu>
 * and Julien Vehent <julien@linuxwall.info>
 *
 * 2012-2014 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
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

#include "structs.h"
#include "convenience.h"
#include "decision_engine.h"

/*!	\file structs.c
 \brief

 This file is intended to provide a place for the struct free functions
 to be placed at. It is not a requirement, as sometimes it makes the code
 easier to read to have the free function next to it's init counterpart.
 */

void free_interface(struct interface *iface) {
    if (likely(iface)) {
        if(iface->filter) {
            pcap_freecode(&iface->pcap_filter);
            free_0(iface->filter);
        }
        free_0(iface->ip);
        free_0(iface->name);
        free_0(iface->tag);
        free_0(iface);
    }
}

void free_handler(struct handler *handler) {
    if (handler) {
        free_0(handler->ip);
        free_0(handler->ip_str);
        free_0(handler->mac);

        GSList *loop = handler->intra_target_ips;
        while(loop) {
        	free(loop->data);
        	loop=loop->next;
        }
        g_slist_free(handler->intra_target_ips);

        free_0(handler->netmask);
        DE_destroy_tree(handler->rule);
        free_0(handler);
    }
}

void free_target(struct target *t) {
    g_mutex_lock(&t->lock);
    free_handler(t->front_handler);
    free_0(t->default_route_mac);
    g_tree_destroy(t->back_handlers);
    g_tree_destroy(t->intra_handlers);
    GSList *loop = t->intra_handlers_list;
    while(loop) {
    	free_handler((struct handler *)(loop->data));
    	loop=loop->next;
    }
    g_slist_free(t->intra_handlers_list);
    DE_destroy_tree(t->control_rule);
    DE_destroy_tree(t->intra_rule);
    g_mutex_clear(&t->lock);
    free_0(t);
}

void free_raw_pcap(struct raw_pcap *raw) {
    free_0(raw->header);
    free_0(raw->packet);
    free_0(raw);
}

void free_pin(struct pin *pin) {
    if(likely(pin)) {
        free_0(pin->pin_key);
        free_0(pin);
    }
}
