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

#define MAX_LIFE 600
#define IDLE_TIMEOUT 60
#define VLAN_TRUNK_INTERFACE "honeynet"

#define check_lan_comm(ip, dst, netmask) \
    ((ip & netmask) == (dst & netmask))

struct vmi_vm {
    gchar *key_ext;
    uint32_t logID;
    uint64_t backendID;
    char *name;
    gint start;
    gint last_seen;

    struct handler *handler;
    struct target *target;

    GCond timeout;
    GMutex lock;

    // To manipulate connections associated
    // we need to keys
    GSList *conn_keys;

    gboolean close;
};

gboolean initialized;
GMutex vmi_lock;
GTree *vmi_vms_ext;
GTree *vmi_vms_int;
GMutex banned_lock;
GTree *bannedIPs;

int vmi_sock;
struct sockaddr_in vmi_addr; /* VMI server address */
unsigned short vmi_port; /* VMI server port */

const char* vmi_log(gpointer data) {
    static char vmi_log_buff[12];
    snprintf(vmi_log_buff, 12, "'%u'", GPOINTER_TO_UINT(data));
    return vmi_log_buff;
}

void open_tcp(int *s) {
    if (!s) return;
    // socket: create the socket
    *s = socket(AF_INET, SOCK_STREAM, 0);
    if (*s < 0) errx(1, "%s: ERROR opening socket", __func__);

    // connect: create a connection with the server
    if (connect(*s, (struct sockaddr *) &vmi_addr, sizeof(vmi_addr)) < 0) errx(
            1, "%s: ERROR connecting", __func__);
}

void close_vmi_vm(struct vmi_vm *vm) {
    //timeout, send signal
    g_mutex_lock(&vmi_lock);

    int fd;
    open_tcp(&fd);
    char *buf = g_malloc0(snprintf(NULL, 0, "close,%s\n", vm->name) + 1);
    sprintf(buf, "close,%s\n", vm->name);
    if (write(fd, buf, strlen(buf)) < 0)
    printdbg( "%s Failed to write to socket!\n", H(1));
    free(buf);
    shutdown(fd, 0);

    // ban the external ip
    g_mutex_lock(&banned_lock);
    if (!g_tree_lookup(bannedIPs, vm->key_ext)) {
        g_tree_insert(bannedIPs, strdup(vm->key_ext), GINT_TO_POINTER(TRUE));
    }
    g_mutex_unlock(&banned_lock);

    // drop any remaining connections
    GSList* loop = vm->conn_keys;
    while (loop) {
        g_mutex_lock(&connlock);
        struct conn_struct *conn = g_tree_lookup(ext_tree1, loop->data);
        g_mutex_unlock(&connlock);

        if (conn) {
            g_mutex_lock(&conn->lock);
            switch_state(conn, DROP);
            g_mutex_unlock(&conn->lock);
        }
        loop = loop->next;
    }

    // remove the vm from the vmi trees
    g_tree_steal(vmi_vms_ext, vm->key_ext);
    g_tree_remove(vmi_vms_int, &vm->backendID);

    // remove the handler from the target
    g_mutex_lock(&vm->target->lock);
    g_tree_remove(vm->target->back_handlers, &vm->backendID);
    g_mutex_unlock(&vm->target->lock);

    g_mutex_unlock(&vmi_lock);

    // free the struct
    g_free(vm->key_ext);
    g_free(vm->name);
    g_mutex_clear(&vm->lock);
    g_cond_clear(&vm->timeout);
    g_slist_free_full(vm->conn_keys, g_free);
    free(vm);
}

void free_vmi_vm(struct vmi_vm *vm) {
    if (vm) {
        g_mutex_lock(&vm->lock);
        vm->close = TRUE;
        g_cond_signal(&vm->timeout);
        g_mutex_unlock(&vm->lock);
    }
}

void* vm_timer(void* data) {
    struct vmi_vm *vm = (struct vmi_vm*) data;
    if(!vm) goto done;

    gint64 sleep_cycle;
    // Wait for timeout or signal
    g_mutex_lock(&vm->lock);
    rewind: sleep_cycle =
            g_get_monotonic_time() + IDLE_TIMEOUT * G_TIME_SPAN_SECOND;
    if (!g_cond_wait_until(&vm->timeout, &vm->lock, sleep_cycle)) {
        printdbg(
                "%s VM timer expired. Sending close signal and shutting down HIH\n", H(1));
    } else {
        //event, restart the timer
        if (!vm->close) goto rewind;
    }

    g_mutex_unlock(&vm->lock);
    close_vmi_vm(vm);

    done:
    pthread_exit(NULL);
    return NULL;
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
        vm->target = pkt->conn->target;
        g_mutex_init(&vm->lock);
        g_cond_init(&vm->timeout);
        pthread_t c;
        pthread_create(&c, NULL, (void *) vm_timer, (void *) vm);
        pthread_detach(c);

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

    // socket: create the socket
    vmi_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (vmi_sock < 0) errx(1, "%s: ERROR opening socket", __func__);

    // build the server's Internet address
    bzero(&vmi_addr, sizeof(vmi_addr));
    vmi_addr.sin_family = AF_INET;
    vmi_addr.sin_addr.s_addr = inet_addr(vmi_server_ip);
    vmi_addr.sin_port = htons(*vmi_server_port);

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

    initialized = TRUE;

    return 0;
}

void close_mod_vmi() {
    if (initialized) {
        g_tree_destroy(vmi_vms_ext);
        g_tree_destroy(vmi_vms_int);
        g_tree_destroy(bannedIPs);
    }
}

mod_result_t mod_vmi_pick(struct mod_args *args) {

    printdbg("%s VMI Backpick Module called\n", H(args->pkt->conn->id));

    if(!initialized) {
        printdbg("%s VMI module is uninitialized!\n");
        return ACCEPT;
    }

    mod_result_t result = REJECT;
    struct vmi_vm *vm = NULL;

    if (args->pkt->in != args->pkt->conn->target->default_route) {
        return result;
    }

    g_mutex_lock(&banned_lock);
    gpointer banned = g_tree_lookup(bannedIPs, args->pkt->src);
    g_mutex_unlock(&banned_lock);

    if (banned) {
        printf("%s Attacker %s is banned from the HIHs!\n",
                H(args->pkt->conn->id), args->pkt->src);
        return result;
    } else {
        //printf("Check if he already uses a clone\n");

        g_mutex_lock(&vmi_lock);
        vm = g_tree_lookup(vmi_vms_ext, args->pkt->src);
        g_mutex_unlock(&vmi_lock);
        if (!vm) vm = get_new_clone(args->pkt, args->pkt->conn);
    }

    if (vm != NULL) {
        printdbg(
                "%s Picking %s (%lu).\n", H(args->pkt->conn->id), vm->name, vm->backendID);
        args->backend_use = vm->backendID;
        result = ACCEPT;

        GTimeVal t;
        g_get_current_time(&t);

        // save the conns here (they could get expired so don't trust this list)
        g_mutex_lock(&vm->lock);
        vm->conn_keys = g_slist_append(vm->conn_keys,
                g_strdup(args->pkt->conn->ext_key));
        vm->last_seen = t.tv_sec;
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

    if(!initialized) {
        printdbg("%s VMI module is uninitialized!\n");
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

    struct addr dst;
    addr_pack(&dst, ADDR_TYPE_IP, 32, &args->pkt->packet.ip->daddr,
            sizeof(ip_addr_t));

    if (!addr_cmp(&dst, &args->pkt->conn->first_pkt_src_ip)) {
        // Packet is a reply in an existing connection
        result = ACCEPT;
    } else if (g_tree_lookup(args->pkt->conn->target->intra_handlers,
            args->pkt->dst)) {
        // Packet is going to a defined INTRA
        result = ACCEPT;
    } else {

        //TODO: Check if intra-lan connection and redirect to INTRA if so
        if (check_lan_comm(
                args->pkt->conn->hih.back_handler->ip->addr_ip,
                args->pkt->packet.ip->daddr,
                args->pkt->conn->hih.back_handler->netmask->addr_ip)) {

            printdbg("%s Intra-lan packet\n", H(1));

            if ((args->pkt->packet.ip->daddr
                    & ~args->pkt->conn->hih.back_handler->netmask->addr_ip)
                    == 255) {
                printdbg("%s Broadcast packet\n", H(1));
            }

            result = ACCEPT;
        } else {

            if (!strcmp(vm->key_ext, args->pkt->dst)) {
                // Connection back to the original IP
                result = ACCEPT;
            } else {

                // TODO: Don't touch DNS, we will use mod_dns_control.

                printdbg(
                        "%s Cought network event, sending signal!\n", H(args->pkt->conn->id));

                vm->close = TRUE;
            }
        }
    }

    g_cond_signal(&vm->timeout);
    g_mutex_unlock(&vm->lock);

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
