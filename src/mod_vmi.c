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

#include <errno.h>

#define ATTACK_TIMEOUT 600
#define VLAN_TRUNK_INTERFACE "honeynet"

GThread *vmi_status_updater = NULL;
GMutex vmi_lock;
GTree *vmi_vms_ext;
GTree *vmi_vms_int;
GTree *bannedIPs;
int vmi_sock;

struct sockaddr_in vmi_addr; /* VMI server address */
unsigned short vmi_port; /* VMI server port */

struct vmi_vm {
    gchar *key_ext;
    uint32_t logID;
    uint64_t backendID;
    char *name;
    gint start;
    gint last_seen;

    struct handler *handler;

    GMutex lock;

    // To manipulate connections associated
    // we need to keys
    GSList *conn_keys;
};

const char* vmi_log(gpointer data) {
    static char vmi_log_buff[12];
    snprintf(vmi_log_buff, 12, "'%u'", GPOINTER_TO_UINT(data));
    return vmi_log_buff;
}

void free_vmi_vm(struct vmi_vm *vm) {
    if (vm) {
        g_free(vm->key_ext);
        g_free(vm->name);
        g_mutex_clear(&vm->lock);

        free(vm);
    }
}

struct vmi_vm *get_new_clone(struct pkt_struct *pkt, struct conn_struct *conn) {

    int n = write(vmi_sock, "random\n", strlen("random\n"));
    if (n < 0) errx(1, "%s ERROR writing to socket\n", __func__);

    char buf[100];
    bzero(buf, 100);
    n = read(vmi_sock, buf, 100);
    if (n <= 0) errx(1, "%s Error receiving from Honeymon!\n", __func__);

    char *nl = strrchr(buf, '\r');
    if (nl) *nl = '\0';
    nl = strrchr(buf, '\n');
    if (nl) *nl = '\0';

    if (strcmp("-", buf)) {

        struct vmi_vm *vm = g_malloc0(sizeof(struct vmi_vm));

        g_mutex_lock(&conn->target->lock);

        // Add new backend handler dynamically to Honeybrid

        conn->target->back_handler_count++;
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
        new_handler->vlan.i =
                htons(atoi(strtok_r(NULL, delim, &p)) & ((1 << 12)-1));
        uint32_t logID = atoi(strtok_r(NULL, delim, &p));

        g_tree_insert(conn->target->back_handlers, key, new_handler);
        g_mutex_unlock(&conn->target->lock);

        GTimeVal t;
        g_get_current_time(&t);

        // We need to pin the attacker's ip and destination ip to this VM

        vm->key_ext = g_strdup(pkt->src);
        vm->handler = new_handler;
        vm->last_seen = t.tv_sec;
        vm->start = vm->last_seen;
        vm->logID = logID;
        vm->backendID = *key;
        g_mutex_init(&vm->lock);

        g_mutex_lock(&vmi_lock);
        g_tree_insert(vmi_vms_ext, vm->key_ext, vm);
        g_tree_insert(vmi_vms_int, &vm->backendID, vm);
        g_mutex_unlock(&vmi_lock);

        return vm;

    } else {
        g_mutex_lock(&vmi_lock);
        g_tree_insert(bannedIPs, (gpointer) strdup(pkt->src), NULL);
        g_mutex_unlock(&vmi_lock);
        return NULL;
    }
}

mod_result_t mod_vmi_front(struct mod_args *args) {
    printdbg("%s VMI Front Module called\n", H(args->pkt->conn->id));

    //printf("Check if attacker is banned..\n");
    //g_tree_foreach(bannedIPs, (GTraverseFunc)find_if_banned,(gpointer)&attacker);
    //if(attacker.banned==0) {
    /*struct vm_search vm;
     vm.srcIP = args->pkt->src;
     vm.vm = NULL;

     g_tree_foreach(vmi_vms, (GTraverseFunc) find_used_vm, &vm);
     if (vm.vm != NULL) {
     g_rw_lock_writer_lock(&(vm.vm->lock));
     if (!vm.vm->paused) {
     GTimeVal t;
     g_get_current_time(&t);
     vm.vm->last_seen = (t.tv_sec);
     }
     g_rw_lock_writer_unlock(&(vm.vm->lock));
     }*/

    return ACCEPT;
}

int init_mod_vmi() {

    gchar *vmi_server_ip, *vmi_server_port;

    if (NULL
            == (vmi_server_ip = (gchar *) g_hash_table_lookup(config,
                    "vmi_server_ip"))) {
        // Not defined so skipping init
        return 0;
    }

    if (NULL
            == (vmi_server_port = (gchar *) g_hash_table_lookup(config,
                    "vmi_server_port"))) {
        errx(1, "%s: VMI Server port not defined!!\n", __func__);
    }

    printdbg("%s Init mod vmi\n", H(22));

    // socket: create the socket
    vmi_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (vmi_sock < 0) errx(1, "%s: ERROR opening socket", __func__);

    // build the server's Internet address
    bzero(&vmi_addr, sizeof(vmi_addr));
    vmi_addr.sin_family = AF_INET;
    vmi_addr.sin_addr.s_addr = inet_addr(vmi_server_ip);
    vmi_addr.sin_port = htons(atoi(vmi_server_port));

    // connect: create a connection with the server
    if (connect(vmi_sock, (struct sockaddr *) &vmi_addr, sizeof(vmi_addr)) < 0) errx(
            1, "%s: ERROR connecting", __func__);

    int n = write(vmi_sock, "hello\n", strlen("hello\n"));
    if (n < 0) errx(1, "%s ERROR writing to socket\n", __func__);

    char buf[100];
    bzero(buf, 100);
    n = read(vmi_sock, buf, 100);
    if (n < 0 || strcmp(buf, "hi 2.1\n\r")) errx(1,
            "%s Error receiving from VMI-Honeymon!\n", __func__);
    else printf("%s VMI-Honeymon is active.\n", H(22));

    vmi_vms_ext = g_tree_new_full((GCompareDataFunc) strcmp, NULL, NULL,
            (GDestroyNotify) free_vmi_vm);
    vmi_vms_int = g_tree_new((GCompareFunc) intcmp);

    bannedIPs = g_tree_new_full((GCompareDataFunc) strcmp, NULL,
            (GDestroyNotify) g_free, NULL);

    return 0;
}

void close_mod_vmi() {
    if (vmi_status_updater) {
        g_thread_join(vmi_status_updater);
    }
}

mod_result_t mod_vmi_pick(struct mod_args *args) {

    printdbg("%s VMI Backpick Module called\n", H(args->pkt->conn->id));

    mod_result_t result = REJECT;
    struct vmi_vm *vm = NULL;

    if (args->pkt->in != args->pkt->conn->target->default_route) {
        return result;
    }

    if (g_tree_lookup(bannedIPs, args->pkt->src)) {
        printf("%s Attacker %s is banned from the HIHs!\n",
                H(args->pkt->conn->id), args->pkt->src);
        return result;
    } else {
        //printf("Check if he already uses a clone\n");

        vm = g_tree_lookup(vmi_vms_ext, args->pkt->src);
        if (!vm) vm = get_new_clone(args->pkt, args->pkt->conn);
    }

    if (vm != NULL) {
        //printf("%s Picking %s (%u).\n", H(args->pkt->conn->id), search.vm->name, search.vm->vmID);
        args->backend_use = vm->backendID;
        result = ACCEPT;

        struct custom_conn_data *log = g_malloc0(
                sizeof(struct custom_conn_data));
        log->data = GUINT_TO_POINTER(vm->logID);
        log->data_print = vmi_log;

        args->pkt->conn->custom_data = g_slist_append(
                args->pkt->conn->custom_data, log);

        // save the conns here (they could get expired so don't trust this list)
        g_mutex_lock(&vm->lock);
        vm->conn_keys = g_slist_append(vm->conn_keys,
                g_strdup(args->pkt->conn->ext_key));
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
    if (args->pkt->in == args->pkt->conn->target->front_handler->iface) {
        return ACCEPT;
    }

    printdbg("%s VMI Control Module called\n", H(args->pkt->conn->id));

    mod_result_t result = REJECT;

    struct vmi_vm *vm = g_tree_lookup(vmi_vms_int, &args->pkt->conn->hih.hihID);

    struct addr dst;
    addr_pack(&dst, ADDR_TYPE_IP, 32, &args->pkt->packet.ip->daddr,
            sizeof(ip_addr_t));

    if (!vm) {
        // Not a VMI HIH
        result = ACCEPT;
    } else if (!addr_cmp(&dst, &args->pkt->conn->first_pkt_src_ip)) {
        // Packet is a reply in an existing connection
        result = ACCEPT;
    } else if (g_tree_lookup(args->pkt->conn->target->intra_handlers,
            args->pkt->dst)) {
        // Packet is going to a defined INTRA
        result = ACCEPT;
    } else {

        //TODO: Check if intra-lan connection and redirect to INTRA if so
        printdbg(
                "%s Cought network event, sending signal!\n", H(args->pkt->conn->id));

        struct custom_conn_data *log = g_malloc0(
                sizeof(struct custom_conn_data));
        log->data = GUINT_TO_POINTER(vm->logID);
        log->data_print = vmi_log;

        char *buf = g_malloc0(
                snprintf(NULL, 0, "%s,%s,%s\n", vm->name,
                        args->pkt->src_with_port, args->pkt->dst_with_port)
                        + 1);
        sprintf(buf, "%s,%s,%s\n", vm->name, args->pkt->src_with_port,
                args->pkt->dst_with_port);
        if (write(vmi_sock, buf, strlen(buf)) < 0)
        printdbg("%s Failed to write to socket!\n", H(args->pkt->conn->id));
        free(buf);

    }

    return result;
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

    if (!strcmp(mode, "front")) return mod_vmi_front(args);
    else if (!strcmp(mode, "pick")) return mod_vmi_pick(args);
    //else if (!strcmp(mode, "back"))
    //  mod_vmi_back(args);
    else if (!strcmp(mode, "control")) return mod_vmi_control(args);

    return DEFER;
}
