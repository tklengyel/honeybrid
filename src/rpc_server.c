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

#include <config.h>
#include "management.h"
#include "log.h"
#include "convenience.h"
#include "globals.h"

#ifdef HAVE_XMLRPC

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>

static xmlrpc_server_abyss_t * server;

static void dieIfFailed(const char * const description, xmlrpc_env const env) {

	if (env.fault_occurred) {
		g_printerr("%s failed. %s\n", description, env.fault_string);
		exit(1);
	}
}

static xmlrpc_value *
rpc_get_number_of_links(xmlrpc_env * const envP,
		__attribute__((unused))   xmlrpc_value * const paramArrayP,
		__attribute__((unused))void * const serverInfo,
		__attribute__((unused))void * const channelInfo) {
	printdbg("%s called!\n", H(9));
	return xmlrpc_build_value(envP, "i", g_hash_table_size(links));
}

static xmlrpc_value *
rpc_get_links(xmlrpc_env * const envP,
		__attribute__((unused))   xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));
	GHashTableIter i;
	char *tag;
	struct interface *iface;
	xmlrpc_value * myArrayP = xmlrpc_array_new(envP);
	ghashtable_foreach(links, i, tag, iface) {
		xmlrpc_value * itemP = xmlrpc_string_new(envP, tag);
		xmlrpc_array_append_item(envP, myArrayP, itemP);
		xmlrpc_DECREF(itemP);
	}
	return myArrayP;
}

static xmlrpc_value *
rpc_add_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));

	struct target *new_target = g_malloc0(sizeof(struct target));

	if (xmlrpc_array_size(envP, paramArrayP)==3) {
		xmlrpc_value *linkp = NULL, *srcipp=NULL, *macp=NULL;
		const char *link = NULL, *mac=NULL, *srcip=NULL;
		xmlrpc_array_read_item(envP, paramArrayP, 0, &linkp);
		xmlrpc_array_read_item(envP, paramArrayP, 1, &macp);
		xmlrpc_array_read_item(envP, paramArrayP, 2, &srcipp);
		xmlrpc_read_string(envP, linkp, &link);
		xmlrpc_read_string(envP, macp, &mac);
		xmlrpc_read_string(envP, srcipp, &srcip);

		struct interface *iface = g_hash_table_lookup(links, link);
		if (iface == NULL) {
			printdbg("%s Target interface is not defined!\n", H(9));
			goto error;
		}

		if (iface->target) {
			printdbg("%s Target default route is already assigned!\n", H(9));
			goto error;
		}

		struct addr *src_ip = (struct addr *) g_malloc0(sizeof(struct addr));
		src_ip->addr_type = ADDR_TYPE_IP;
		src_ip->addr_bits = 32;
		if (addr_pton(srcip, src_ip) < 0) {
			printdbg("%s Illegal IP address\n", H(9));
			free(src_ip);
			goto error;
		}

		struct addr *mac_addr = (struct addr *) g_malloc0(sizeof(struct addr));
		mac_addr->addr_type = ADDR_TYPE_ETH;
		mac_addr->addr_bits = 32;
		if (addr_pton(mac, mac_addr) < 0) {
			printdbg("%s Illegal MAC address\n", H(9));
			free(src_ip);
			free(mac_addr);
			goto error;
		}

		iface->target = new_target;
		new_target->default_route = iface;
		new_target->default_route_ip = src_ip;
		new_target->default_route_mac = mac_addr;
	}

	if (NOK == add_target(new_target))
		goto error;

	return xmlrpc_build_value(envP, "i", new_target->targetID);

error:
    free(new_target);
	return xmlrpc_build_value(envP, "i", 0);

}

static xmlrpc_value *
rpc_remove_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));

	xmlrpc_int64 targetID = 0;
	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &targetID);

	if (targetID && OK == remove_target(targetID)) {
		return xmlrpc_build_value(envP, "i", 1);
	}

	return xmlrpc_build_value(envP, "i", 0);
}

static xmlrpc_value *
rpc_add_backend(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));

	struct handler *backend = g_malloc0(sizeof(struct handler));
	struct target *target = NULL;

	if (xmlrpc_array_size(envP, paramArrayP) != 7)
		goto error;

	xmlrpc_value *values[7] = { 0 };
	int i = 0;
	for (; i < 7; i++) {
		xmlrpc_array_read_item(envP, paramArrayP, i, &values[i]);

		switch (i) {
		case 0: {
			xmlrpc_int64 targetID = 0;
			xmlrpc_read_i8(envP, values[i], &targetID);
			target = g_tree_lookup(targets, &targetID);
			if (!target)
				goto error;
			break;
		}
		case 1: {
			xmlrpc_value *linkp = NULL;
			const char *link = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &linkp);
			xmlrpc_read_string(envP, linkp, &link);
			backend->iface = g_hash_table_lookup(links, link);
			if (!backend->iface)
				goto error;
			break;
		}
		case 2: {
			xmlrpc_value *ipp = NULL;
			const char *ip = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &ipp);
			xmlrpc_read_string(envP, ipp, &ip);
			backend->ip = g_malloc0(sizeof(struct addr));
	        backend->ip->addr_type = ADDR_TYPE_IP;
	        backend->ip->addr_bits = 32;
			if (addr_pton(ip, backend->ip) < 0) {
				goto error;
			}
			break;
		}
		case 3: {
			xmlrpc_value *macp = NULL;
			const char *mac = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &macp);
			xmlrpc_read_string(envP, macp, &mac);
			backend->mac = g_malloc0(sizeof(struct addr));
	        backend->mac->addr_type = ADDR_TYPE_ETH;
	        backend->mac->addr_bits = 32;
			if (addr_pton(mac, backend->mac) < 0) {
				goto error;
			}
			break;
		}
		case 4: {
			xmlrpc_value *maskp = NULL;
			const char *mask = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &maskp);
			xmlrpc_read_string(envP, maskp, &mask);
			backend->netmask = g_malloc0(sizeof(struct addr));
			if (addr_pton(mask, backend->netmask) < 0) {
				goto error;
			}
			break;
		}
		case 5: {
			xmlrpc_value *vlanp = NULL;
			int vlan;
			xmlrpc_array_read_item(envP, paramArrayP, i, &vlanp);
			xmlrpc_read_int(envP, vlanp, &vlan);
			backend->vlan.i = htons(vlan & BIT_MASK(0,11));
			break;
		}
		case 6: {
			xmlrpc_value *rulep = NULL;
			const char *rule = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &rulep);
			xmlrpc_read_string(envP, rulep, &rule);
			backend->rule = DE_create_tree(rule);
			break;
		}
		case 7: {
			xmlrpc_value *exp = NULL;
			int ex;
			xmlrpc_array_read_item(envP, paramArrayP, i, &exp);
			xmlrpc_read_int(envP, exp, &ex);
			if(ex>0) backend->exclusive = 1;
			break;
		}
		}
	}

	if(OK==add_back_handler(target, backend)) {
		xmlrpc_build_value(envP, "i", backend->ID);
	}

	error:
	free_handler(backend);
	return xmlrpc_build_value(envP, "i", 0);
}

static xmlrpc_value *
rpc_remove_backend(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));

	xmlrpc_int64 targetID = 0, backendID = 0;
	xmlrpc_decompose_value(envP, paramArrayP, "(ii)", &targetID, &backendID);

	if (targetID && backendID) {
		struct target *target = g_tree_lookup(targets, &targetID);
		if (target && OK == remove_back_handler(target, backendID)) {
			return xmlrpc_build_value(envP, "i", 1);
		}
	}

	return xmlrpc_build_value(envP, "i", 0);
}

static xmlrpc_value *
rpc_add_intra(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));

	struct handler *intra = g_malloc0(sizeof(struct handler));
	struct target *target = NULL;
	struct addr *target_ip = NULL;

	if (xmlrpc_array_size(envP, paramArrayP) != 8)
		goto error;

	xmlrpc_value *values[8] = { 0 };
	int i = 0;
	for (; i < 8; i++) {
		xmlrpc_array_read_item(envP, paramArrayP, i, &values[i]);

		switch (i) {
		case 0: {
			xmlrpc_int64 targetID = 0;
			xmlrpc_read_i8(envP, values[i], &targetID);
			target = g_tree_lookup(targets, &targetID);
			if (!target)
				goto error;
			break;
		}
		case 1: {
			xmlrpc_value *linkp = NULL;
			const char *link = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &linkp);
			xmlrpc_read_string(envP, linkp, &link);
			intra->iface = g_hash_table_lookup(links, link);
			if (!intra->iface)
				goto error;
			break;
		}
		case 2: {
			xmlrpc_value *ipp = NULL;
			const char *ip = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &ipp);
			xmlrpc_read_string(envP, ipp, &ip);
			intra->ip = g_malloc0(sizeof(struct addr));
			intra->ip->addr_type = ADDR_TYPE_IP;
			intra->ip->addr_bits = 32;
			if (addr_pton(ip, intra->ip) < 0) {
				goto error;
			}
			break;
		}
		case 3: {
			xmlrpc_value *macp = NULL;
			const char *mac = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &macp);
			xmlrpc_read_string(envP, macp, &mac);
			intra->mac = g_malloc0(sizeof(struct addr));
			intra->mac->addr_type = ADDR_TYPE_ETH;
			intra->mac->addr_bits = 32;
			if (addr_pton(mac, intra->mac) < 0) {
				goto error;
			}
			break;
		}
		case 4: {
			xmlrpc_value *maskp = NULL;
			const char *mask = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &maskp);
			xmlrpc_read_string(envP, maskp, &mask);
			intra->netmask = g_malloc0(sizeof(struct addr));
			if (addr_pton(mask, intra->netmask) < 0) {
				goto error;
			}
			break;
		}
		case 5: {
			xmlrpc_value *vlanp = NULL;
			int vlan;
			xmlrpc_array_read_item(envP, paramArrayP, i, &vlanp);
			xmlrpc_read_int(envP, vlanp, &vlan);
			intra->vlan.i = htons(vlan & BIT_MASK(0,11));
			break;
		}
		case 6: {
			xmlrpc_value *rulep = NULL;
			const char *rule = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &rulep);
			xmlrpc_read_string(envP, rulep, &rule);
			intra->rule = DE_create_tree(rule);
			break;
		}
		case 7: {
			xmlrpc_value *exp = NULL;
			int ex;
			xmlrpc_array_read_item(envP, paramArrayP, i, &exp);
			xmlrpc_read_int(envP, exp, &ex);
			if (ex > 0)
				intra->exclusive = 1;
			break;
		}
		case 8: {
			xmlrpc_value *ipp = NULL;
			const char *ip = NULL;
			xmlrpc_array_read_item(envP, paramArrayP, i, &ipp);
			xmlrpc_read_string(envP, ipp, &ip);
			target_ip = g_malloc0(sizeof(struct addr));
			target_ip->addr_type = ADDR_TYPE_IP;
			target_ip->addr_bits = 32;
			if (addr_pton(ip, target_ip) < 0) {
				goto error;
			}
			break;
		}
		}
	}

	if(OK==add_intra_handler(target, target_ip, intra)) {
		xmlrpc_build_value(envP, "i", intra->ID);
	}

	error:
	free_handler(intra);
	return xmlrpc_build_value(envP, "i", 0);
}

static xmlrpc_value *
rpc_remove_intra(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP,
		__attribute__((unused)) void * const serverInfo,
		__attribute__((unused)) void * const channelInfo) {
	printdbg("%s called!\n", H(9));

	xmlrpc_int64 targetID = 0, intraID = 0;
	xmlrpc_decompose_value(envP, paramArrayP, "(ii)", &targetID, &intraID);

	if (targetID && intraID) {
		struct target *target = g_tree_lookup(targets, &targetID);
		if (target && OK == remove_intra_handler(target, intraID)) {
			return xmlrpc_build_value(envP, "i", 1);
		}
	}

	return xmlrpc_build_value(envP, "i", 0);
}

/******************************************************************************/

enum honeybrid_rpc_function {
	GET_NUMBER_OF_LINKS,
	GET_LINKS,
	ADD_TARGET,
	REMOVE_TARGET,
	ADD_BACKEND,
	REMOVE_BACKEND,
	ADD_INTRA,
	REMOVE_INTRA,

	__MAX_RPC_FUNCTIONS
};

struct xmlrpc_method_info3
const method[__MAX_RPC_FUNCTIONS] = {
	[GET_NUMBER_OF_LINKS] =
		{ 	.methodName = "get_number_of_links",
			.methodFunction = &rpc_get_number_of_links },
	[GET_LINKS]	=
		{ 	.methodName = "get_links",
			.methodFunction = &rpc_get_links },
	[ADD_TARGET]	=
		{ 	.methodName = "add_target",
			.methodFunction = &rpc_add_target },
	[REMOVE_TARGET] =
		{ 	.methodName = "remove_target",
			.methodFunction = &rpc_remove_target },
	[ADD_BACKEND] =
		{ 	.methodName = "add_backend",
			.methodFunction = &rpc_add_backend },
	[REMOVE_BACKEND] =
		{ 	.methodName = "remove_backend",
			.methodFunction = &rpc_remove_backend },
	[ADD_INTRA] =
		{ 	.methodName = "add_inra",
			.methodFunction = &rpc_add_intra },
	[REMOVE_INTRA] =
		{ 	.methodName = "remove_intra",
			.methodFunction = &rpc_remove_intra },
};

/******************************************************************************/

void rpc_server_thread() {
	xmlrpc_server_abyss_parms serverparm;
	xmlrpc_registry * registryP;
	xmlrpc_env env;

	xmlrpc_env_init(&env);

	xmlrpc_server_abyss_global_init(&env);
	dieIfFailed("xmlrpc_server_abyss_global_init", env);

	registryP = xmlrpc_registry_new(&env);
	dieIfFailed("xmlrpc_registry_new", env);

	int i;
	for(i=0;i<__MAX_RPC_FUNCTIONS;i++) {
		xmlrpc_registry_add_method3(&env, registryP, &method[i]);
	}

	dieIfFailed("xmlrpc_registry_add_method2", env);

	serverparm.registryP = registryP;
	serverparm.port_number = ICONFIG("xmlrpc_server_port");
	serverparm.config_file_name = CONFIG("xmlrpc_server_log");

	xmlrpc_server_abyss_create(&env, &serverparm, XMLRPC_APSIZE(port_number),
			&server);
	dieIfFailed("xmlrpc_server_abyss_create", env);

	xmlrpc_server_abyss_run_server(&env, server);
	dieIfFailed("xmlrpc_server_abyss_run_server", env);

	printdbg("%s XML-RPC Server has terminated\n", H(0));

	xmlrpc_server_abyss_destroy(server);
	xmlrpc_registry_free(registryP);
	xmlrpc_server_abyss_global_term();
	xmlrpc_env_clean(&env);
}

void rpc_server_die_signal() {
	while (OK == threading) {
		g_mutex_lock(&threading_cond_lock);
		g_cond_wait(&threading_cond, &threading_cond_lock);
		g_mutex_unlock(&threading_cond_lock);
	}

	xmlrpc_env env;
	xmlrpc_env_init(&env);
	xmlrpc_server_abyss_terminate(&env, server);
	dieIfFailed("xmlrpc_server_abyss_terminate", env);
	xmlrpc_env_clean(&env);
}

void close_rpc_server() {
	if (server) {
		g_thread_join(rpc_server);
		g_thread_join(rpc_server_kill);
	}
}

void init_rpc_server() {
	if (ICONFIG("xmlrpc_server_port")) {
		if ((rpc_server = g_thread_new("rpcserver", (void *) rpc_server_thread,
				NULL)) == NULL) {
			errx(1, "%s Unable to start the XMLRPC Server thread", __func__);
		} else {
			printdbg("%s XMLRPC Server thread started\n", H(0));
		}

		if ((rpc_server_kill = g_thread_new("rpcserverkill",
				(void *) rpc_server_die_signal, NULL)) == NULL) {
			errx(1, "%s Unable to start the XMLRPC Server kill signal thread",
					__func__);
		} else {
			printdbg("%s XMLRPC Server kill signal thread started\n", H(0));
		}
	} else {
		server = NULL;
	}
}
#else
void init_rpc_server() {}
void close_rpc_server() {}
#endif
