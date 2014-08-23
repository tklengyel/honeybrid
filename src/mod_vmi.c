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

#include "modules.h"

#ifndef HAVE_XMLRPC

int init_mod_vmi() {}
void close_mod_vmi() {}
mod_result_t mod_vmi(struct mod_args *args) {
    return DEFER;
}

#else /* HAVE_XMLRPC */

#include <errno.h>

#define MAX_LIFE        600
#define IDLE_TIMEOUT    60
#define VLAN_TRUNK_INTERFACE "honeynet"

#define check_lan_comm(ip, dst, netmask) \
    ((ip & netmask) == (dst & netmask))

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

static xmlrpc_env env;

static void
dieIfFaultOccurred (xmlrpc_env * const envP) {
    if (envP->fault_occurred) {
        fprintf(stderr, "ERROR: %s (%d)\n",
                envP->fault_string, envP->fault_code);
        exit(1);
    }
}

struct vmi_vm {
	ip_addr_t key_ext;
	uint32_t logID;
	uint64_t backendID;
	char *name;
	GTimer *start;

	struct handler *handler;
	struct target *target;

	gboolean signal;
	GCond timeout;
	GMutex lock;

	// To manipulate connections associated
	// we need to keys
	GSList *conn_keys;

	gboolean close;
};

static GString *vmi_server;
static gboolean initialized;
static GMutex vmi_lock;
static GTree *vmi_vms_ext;
static GTree *vmi_vms_int;
static GMutex banned_lock;
static GTree *bannedIPs;

void* vm_timer(void* data) {
	struct vmi_vm *vm = (struct vmi_vm*) data;
	if (!vm)
		goto done;

	gint64 sleep_cycle;
	// Wait for timeout or signal
	g_mutex_lock(&vm->lock);
	rewind: sleep_cycle =
			g_get_monotonic_time() + IDLE_TIMEOUT * G_TIME_SPAN_SECOND;
	while (!vm->close) {
		if (!g_cond_wait_until(&vm->timeout, &vm->lock, sleep_cycle)) {
			printdbg(
					"%s VM timer expired on %s. Sending close signal and shutting down HIH\n", H(1), vm->name);
			break;
		} else {
			if (vm->signal) {
				vm->signal = FALSE;

				//event, restart the timer
				if (!vm->close)
					goto rewind;
			}
		}
	}

	g_mutex_unlock(&vm->lock);
	//close_vmi_vm(vm);

	done: pthread_exit(NULL);
	return NULL;
}

struct vmi_vm *get_new_clone(struct pkt_struct *pkt, struct conn_struct *conn) {

		struct vmi_vm *vm = g_malloc0(sizeof(struct vmi_vm));

		g_mutex_lock(&conn->target->lock);

		// Add new backend handler dynamically to Honeybrid

		/*conn->target->back_handler_count++;
		uint64_t *key = malloc(sizeof(uint64_t));
		*key = conn->target->back_handler_count;

		struct handler *new_handler = g_malloc0(sizeof(struct handler));
		new_handler->mac = g_malloc0(sizeof(struct addr));
		new_handler->ip = g_malloc0(sizeof(struct addr));
		new_handler->netmask = g_malloc0(sizeof(struct addr));
		addr_pton("255.255.255.0", new_handler->netmask);

		char *p;
		char delim[] = ",";
		vm->name = g_strdup(strtok_r(buf, delim, &p));
		addr_pton(strtok_r(NULL, delim, &p), new_handler->ip);
		new_handler->ip_str = g_strdup(addr_ntoa(new_handler->ip));
		new_handler->iface = g_hash_table_lookup(links, VLAN_TRUNK_INTERFACE);
		addr_pton(strtok_r(NULL, delim, &p), new_handler->mac);
		new_handler->vlan.i = htons(
				atoi(strtok_r(NULL, delim, &p)) & ((1 << 12) - 1));
		uint32_t logID = atoi(strtok_r(NULL, delim, &p));

		g_tree_insert(conn->target->back_handlers, key, new_handler);
		g_mutex_unlock(&conn->target->lock);

		// We need to pin the attacker's ip and destination ip to this VM


		vm->key_ext = pkt->packet.ip->saddr;
		vm->handler = new_handler;
		vm->start = g_timer_new();
		vm->logID = logID;
		vm->backendID = *key;
		vm->target = pkt->conn->target;
		g_mutex_init(&vm->lock);
		g_cond_init(&vm->timeout);
		pthread_t c;
		pthread_create(&c, NULL, (void *) vm_timer, (void *) vm);
		pthread_detach(c);

		g_mutex_lock(&vmi_lock);
		g_tree_insert(vmi_vms_ext, &vm->key_ext, vm);
		g_tree_insert(vmi_vms_int, &vm->backendID, vm);
		g_mutex_unlock(&vmi_lock);

		return vm;

	} else {
		g_mutex_lock(&vmi_lock);
		uint32_t *banned = g_memdup(&pkt->packet.ip->saddr, sizeof(uint32_t));
		g_tree_insert(bannedIPs, banned, NULL);
		g_mutex_unlock(&vmi_lock);
		return NULL;
	}*/
}

int init_mod_vmi() {

	gchar *vmi_server_ip;
	int *vmi_server_port;

	if (NULL
			== (vmi_server_ip = (gchar *) g_hash_table_lookup(config,
					"vmi_server_ip"))) {
		// Not defined so skipping init
		initialized = FALSE;
		return 0;
	}

	if (NULL
			== (vmi_server_port = g_hash_table_lookup(config, "vmi_server_port"))) {
		errx(1, "%s: VMI Server port not defined!!\n", __func__);
	}

	printdbg(
			"%s Init mod_vmi. VMI-Honeymon is defined at %s:%i\n", H(22), vmi_server_ip, *vmi_server_port);


	g_string_printf(vmi_server, "http://%s:%i/RPC2", vmi_server_ip, *vmi_server_port);


	const char *test = NULL;
	xmlrpc_env_init(&env);
	xmlrpc_client_init2(&env, XMLRPC_CLIENT_NO_FLAGS, vmi_server->str, VERSION, NULL, 0);

	printf("Making 'ECHO TEST' XMLRPC call to VMI-Honeymon on URL '%s'\n", vmi_server->str);

	/* Make the remote procedure call */
	xmlrpc_value *resultP = xmlrpc_client_call(&env, vmi_server->str, "echo_test", "(i)",
			(xmlrpc_int32) 1);
	xmlrpc_read_string(&env, resultP, &test);
	dieIfFaultOccurred(&env);
	printf("Got reply: %s\n", test);

	bannedIPs = g_tree_new_full((GCompareDataFunc) intcmp, NULL,
			(GDestroyNotify) g_free, NULL);

	initialized = TRUE;

	return 0;
}

void close_mod_vmi() {
	if (initialized) {
		g_tree_destroy(vmi_vms_ext);
		g_tree_destroy(vmi_vms_int);
		g_tree_destroy(bannedIPs);

		/* Clean up our error-handling environment. */
		xmlrpc_env_clean(&env);

		/* Shutdown our XML-RPC client library. */
		xmlrpc_client_cleanup();
	}
}

mod_result_t mod_vmi_pick(struct mod_args *args) {

	printdbg("%s VMI Backpick Module called\n", H(args->pkt->conn->id));

	if (!initialized) {
		printdbg("%s VMI module is uninitialized!\n", H(1));
		return ACCEPT;
	}

	mod_result_t result = REJECT;
	struct vmi_vm *vm = NULL;

	if (args->pkt->in != args->pkt->conn->target->default_route) {
		return result;
	}

	g_mutex_lock(&banned_lock);
	gpointer banned = g_tree_lookup(bannedIPs, &args->pkt->packet.ip->saddr);
	g_mutex_unlock(&banned_lock);

	if (banned) {
		printf("%s Attacker %"PRIx32" is banned from the HIHs!\n",
				H(args->pkt->conn->id), args->pkt->packet.ip->saddr);
		return result;
	} else {
		//printf("Check if he already uses a clone\n");

		g_mutex_lock(&vmi_lock);
		vm = g_tree_lookup(vmi_vms_ext, &args->pkt->packet.ip->saddr);
		g_mutex_unlock(&vmi_lock);
		if (!vm)
			vm = get_new_clone(args->pkt, args->pkt->conn);
	}

	if (vm != NULL) {
		printdbg(
				"%s Picking %s (%lu).\n", H(args->pkt->conn->id), vm->name, vm->backendID);
		args->backend_use = vm->backendID;
		result = ACCEPT;

		// save the conns here (they could get expired so don't trust this list)
		g_mutex_lock(&vm->lock);
		vm->conn_keys = g_slist_append(vm->conn_keys,
				g_memdup(args->pkt->conn->ext_key, sizeof(struct conn_key)));
		g_mutex_unlock(&vm->lock);

	} else {
		printdbg(
				"%s No available backend found, rejecting!\n", H(args->pkt->conn->id));
		result = REJECT;
	}

	return result;
}

mod_result_t mod_vmi_control(struct mod_args *args) {
	// Only control packets coming from the backends
	if (args->pkt->origin != HIH) {
		return ACCEPT;
	}

	if (!initialized) {
		printdbg("%s VMI module is uninitialized!\n", H(0));
		return ACCEPT;
	}

	printdbg("%s VMI Control Module called\n", H(args->pkt->conn->id));

	mod_result_t result = REJECT;

	g_mutex_lock(&vmi_lock);
	struct vmi_vm *vm = g_tree_lookup(vmi_vms_int, &args->pkt->conn->hih.hihID);
	g_mutex_unlock(&vmi_lock);

	if (!vm) {
		// Not a VMI HIH
		return ACCEPT;
	}

	g_mutex_lock(&vm->lock);

	if (g_timer_elapsed(vm->start, NULL) > MAX_LIFE) {
		printdbg(
				"%s VM max life expired, sending signal!\n", H(args->pkt->conn->id));

		vm->close = TRUE;
		goto signal;
	}

	struct addr dst;
	addr_pack(&dst, ADDR_TYPE_IP, 32, &args->pkt->packet.ip->daddr,
			sizeof(ip_addr_t));

	if (!addr_cmp(&dst, &args->pkt->conn->first_pkt_src_ip)) {
		// Packet is a reply in an existing connection
		result = ACCEPT;
	} else if (vm->key_ext == args->pkt->packet.ip->daddr) {
		// Connection back to the original IP
		result = ACCEPT;
	} else {

		// TODO: Don't touch DNS, we will use mod_dns_control.

		printdbg(
				"%s Cought network event, sending signal!\n", H(args->pkt->conn->id));

		vm->close = TRUE;
	}

	vm->signal = TRUE;
	signal: g_cond_signal(&vm->timeout);
	g_mutex_unlock(&vm->lock);

	return result;
}

mod_result_t mod_vmi_intra(struct mod_args *args) {
	return DEFER;
}

mod_result_t mod_vmi(struct mod_args *args) {

	gchar *mode;
	// get the backup file for this module
	if (NULL
			== (mode = (gchar *) g_hash_table_lookup(args->node->config, "mode"))) {
		// We can't decide
		printdbg(
				"%s mandatory argument 'mode' undefined (back/control)!\n", H(args->pkt->conn->id));
		return DEFER;
	}
	//else
	//printf("VMI Mode %s\n", mode);

	else if (!strcmp(mode, "pick"))
		return mod_vmi_pick(args);
	//else if (!strcmp(mode, "back"))
	//  mod_vmi_back(args);
	else if (!strcmp(mode, "control"))
		return mod_vmi_control(args);
	else if (!strcmp(mode, "intra"))
		return mod_vmi_intra(args);

	return DEFER;
}

#endif
