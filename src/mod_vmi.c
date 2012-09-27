/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#include "decision_engine.h"
#include "modules.h"
#include "netcode.h"

#define ATTACK_TIMEOUT 600

GTree *vmi_vms;
GTree *bannedIPs;
int vmi_sock;

struct sockaddr_in vmi_addr;    /* VMI server address */
unsigned short vmi_port;    /* VMI server port */

/*struct vmi_msg {
	char *vm_name;
	char *attacker;
	char *conn_out;
};*/

struct vm_search {
	gchar *srcIP;
	uint32_t vmID;
};

struct attacker_search {
	gchar *outIP;
	gchar *attacker;
	uint32_t mark;

	char *vmName;
	gint found;
	gint event;
};

struct vmi_vm {
	gchar *attacker;
	char *name;
	uint32_t vmID;
	uint32_t logID;
	int socket;
	int paused;
	gint start;
	gint event;

	pthread_mutex_t lock;
};

/*void free_vmi_msg(gpointer data) {
        struct vmi_msg *tofree = (struct vmi_msg *)data;
	if(tofree->vm_name!=NULL)
		free(tofree->vm_name);
	if(tofree->attacker!=NULL)
		free(tofree->attacker);
	if(tofree->conn_out!=NULL)
		free(tofree->conn_out);
        free(tofree);
}*/

void noop(gpointer data) {}

void free_vmi_vm(gpointer data) {
	struct vmi_vm *vm=(struct vmi_vm *)data;
        if(vm->attacker!=NULL)
		free(vm->attacker);
	if(vm->name!=NULL)
		free(vm->name);

	pthread_mutex_destroy(&(vm->lock));
        free(vm);
}

// Each backend
gboolean build_vmi_vms2(gpointer key, gpointer value, gpointer data) {

	//int *vmi_sock=(int *)data;
	char *vm_name=(char *)value;
	char vmi_buffer[100];
	bzero(vmi_buffer,100);
	sprintf(vmi_buffer,"status,%s\n", vm_name);

	//printf("Sending on socket %i: %s", vmi_sock, vmi_buffer);

	if ( write(vmi_sock, vmi_buffer, strlen(vmi_buffer)) < 0) {
		g_printerr("%s Couldn't send message to VMI server\n", H(22));
	} else {
		bzero(vmi_buffer,100);

 		if ( read(vmi_sock, vmi_buffer, 100) < 0) {
         		printf("%s Didn't get any message back!\n", H(22));
		} else {

			char *nl = strrchr(vmi_buffer, '\r');
                	if (nl) *nl = '\0';
                	nl = strrchr(vmi_buffer, '\n');
                	if (nl) *nl = '\0';

			if(!strcmp(vmi_buffer,"active")) {
				g_printerr("%s VM %s is active, pausing!\n", H(22), (char *)value);

				bzero(vmi_buffer,100);
				sprintf(vmi_buffer,"pause,%s\n", vm_name);
				write(vmi_sock, vmi_buffer, strlen(vmi_buffer));
				bzero(vmi_buffer,100);
				read(vmi_sock, vmi_buffer, 100);
				if(strcmp(vmi_buffer,"paused\n\r")) {
					g_printerr("%s VM was not paused on our request, skipping\n",H(22));
					return FALSE;
				}
				else
					g_printerr("%s VM was paused, enabling\n",H(22));

				struct vmi_vm *vm=g_malloc0(sizeof(struct vmi_vm));

				vm->vmID=*(uint32_t*)key;
				vm->name=strdup(vm_name);
				vm->attacker=NULL;
				vm->paused=1;
				vm->event=0;

				pthread_mutex_init(&(vm->lock),NULL);

				g_tree_insert(vmi_vms, key, (gpointer)vm);
			} else
			if(!strcmp(vmi_buffer,"paused")) {

				g_printerr("%s VM %s is paused, enabling!\n", H(22), (char *)value);
                                struct vmi_vm *vm=g_malloc0(sizeof(struct vmi_vm));

                                vm->vmID=*(uint32_t*)key;
                                vm->name=strdup(vm_name);
                                vm->attacker=NULL;
				vm->paused=1;
				vm->logID=0;
				vm->event=0;

                                pthread_mutex_init(&(vm->lock),NULL);

                                g_tree_insert(vmi_vms, key, (gpointer)vm);

			} else
				g_printerr("%s VM %s is inactive!\n",H(22), (char *)value);
		}
	}

	return FALSE;
}

// Loop each target
void build_vmi_vms(gpointer data, gpointer user_data) {

	struct target *t=(struct target *)data;
	g_tree_foreach(t->back_tags, (GTraverseFunc)build_vmi_vms2, user_data);

}

gboolean find_free_vm(gpointer key, gpointer value, gpointer data) {

	uint32_t *vmID=(uint32_t *)key;
	struct vmi_vm *vm=(struct vmi_vm *)value;
	struct vm_search *search=(struct vm_search *)data;
	int found=0;

	printf("Searching for free VM: %s (%u)\n", vm->name, *vmID);

	pthread_mutex_lock(&(vm->lock));

	if(vm->paused) {

		char buf[100];
		bzero(buf,100);
		sprintf(buf, "activate,%s\n",vm->name);

		int n = write(vmi_sock, buf, strlen(buf));
        	if (n < 0)
                	errx(1,"%s ERROR writing to socket\n",__func__);

		bzero(buf,100);
		n = read(vmi_sock, buf, 100);
        	if(n<=0)
                	errx(1,"%s Error receiving from Honeymon!\n",__func__);

		char *p;
		char delim[]=",";
		strtok_r(buf,delim,&p);
		vm->logID=atoi(strtok_r(NULL,delim,&p));
		vm->paused=0;
		vm->attacker=g_strdup(search->srcIP);
		GTimeVal t;
	        g_get_current_time(&t);
        	vm->start = (t.tv_sec);
		vm->event=0;

		search->vmID=*vmID;
		found=1;

		g_printerr("%s Found free VM and activated it: %u!\n", H(22), *vmID);

	}
	pthread_mutex_unlock(&(vm->lock));

	if(found)
		return TRUE;
	else
		return FALSE;
}

gboolean find_used_vm(gpointer key, gpointer value, gpointer data) {
	uint32_t *vmID=(uint32_t *)key;
        struct vmi_vm *vm=(struct vmi_vm *)value;
        struct vm_search *search=(struct vm_search *)data;

	if(!vm->paused && !strcmp(search->srcIP, vm->attacker)) {

		char buf[100];
		bzero(buf,100);
		sprintf(buf,"status,%s\n",vm->name);
		write(vmi_sock, buf, strlen(buf));
		bzero(buf,100);
		read(vmi_sock,buf,100);
		if(!strcmp(buf,"paused\n\r")) {
			vm->paused=1;
			free(vm->attacker);
			vm->attacker=NULL;
		} else {
			printf("This attacker is already using a VM: %u\n", *vmID);
			search->vmID=*vmID;
			return TRUE;
		}
	}

	return FALSE;
}

void mod_vmi_pick(struct mod_args *args)
{

	g_printerr("%s VMI Backpick Module called\n", H(args->pkt->conn->id));

	struct vm_search search;
	gchar **values=g_strsplit( args->pkt->key_src, ":", 0);
        search.srcIP = values[0];
	search.vmID=0;

	g_tree_foreach(vmi_vms, (GTraverseFunc)find_used_vm, (gpointer)&search);

	if(search.vmID==0) {
		g_tree_foreach(vmi_vms, (GTraverseFunc)find_free_vm, (gpointer)&search);
	}

	if(search.vmID!=0) {
		//printf("%s Picking %u.\n", H(args->pkt->conn->id), free_vm);
                args->backend_use=search.vmID;
                args->node->result = 1;
	} else {
		g_printerr("%s No available backend found, rejecting!\n", H(args->pkt->conn->id));
		args->node->result = 0;
	}

	g_strfreev(values);
}

void mod_vmi_back(struct mod_args *args)
{
	g_printerr("%s VMI Back Module called\n", H(args->pkt->conn->id));

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	// Check if IP is banned (exceeded allowed time-frame)
	gchar **key_src;
        key_src = g_strsplit( args->pkt->key_src, ":", 0);
	gint *start=(gint *)g_tree_lookup(bannedIPs, key_src[0]);
	g_strfreev(key_src);

	if(start!=NULL && now-(*start)>ATTACK_TIMEOUT) {
		args->node->result = 0;
		return;
	}

	int n=write(vmi_sock, "free\n", strlen("free\n"));

	if(n<=0) { args->node->result = 0; return; }

	char buf[100];
	bzero(buf,100);
	n=read(vmi_sock,buf,100);

	if(n<=0) { args->node->result = 0; return; }

	char *nl = strrchr(buf, '\r');
        if (nl) *nl = '\0';
        nl = strrchr(buf, '\n');
        if (nl) *nl = '\0';

	int free=atoi(buf);

	if(free>0) {
		args->node->result = 1;

		key_src = g_strsplit( args->pkt->key_src, ":", 0);
		char *attacker=strdup(key_src[0]);
		g_strfreev(key_src);
		gint *startTime=malloc(sizeof(gint));
		*startTime=now;

		g_tree_insert(bannedIPs, (gpointer)attacker, (gpointer)startTime);
	}
	else		args->node->result = 0;

}

gboolean control_check_attacker(gpointer key, gpointer value, gpointer data) {
	struct vmi_vm *vm=(struct vmi_vm *)value;
	struct attacker_search *search=(struct attacker_search *)data;
	uint32_t vmID=*(uint32_t *)key;

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	if(!vm->paused && vmID==search->mark && now-(vm->start)<=ATTACK_TIMEOUT) {
		search->found=1;
		search->vmName=strdup(vm->name);
		search->attacker=strdup(vm->attacker);

		if(vm->event)
			search->event=1;
		else
		// Is the clone going somewhere else than the attacker?
		if(strcmp(search->attacker, vm->attacker)) {
			search->event=1;
			vm->event=1;
		}

		return TRUE;
	} else
	return FALSE;
}

void mod_vmi_control(struct mod_args *args)
{
	// Only control packets coming from the clones
	if(args->pkt->mark==0) {
		args->node->result = 1;
		return;
	}

	g_printerr("%s VMI Control Module called\n", H(args->pkt->conn->id));

	/*! get the IP address from the packet */
	gchar **key_dst;
	//key_src = g_strsplit( args->pkt->key_src, ":", 0);
	key_dst =  g_strsplit(args->pkt->key_dst, ":", 2);

	//g_printerr("%s source IP is %s\n", H(args->pkt->conn->id), key_src[0]);

	struct attacker_search search;
	search.found=0;
	search.event=0;
	search.outIP=key_dst[0];
	search.attacker=NULL;
	search.mark=args->pkt->mark;
	search.vmName=NULL;

	g_tree_foreach(vmi_vms, (GTraverseFunc)control_check_attacker, (gpointer)&search);

	if(search.found && search.vmName!=NULL) {
		if(search.event) {
			g_printerr("%s Cought network event, sending signal!\n", H(args->pkt->conn->id));
			args->node->result = 0;

			char *buf = g_malloc0(snprintf(NULL, 0, "%s,%s,%s\n", search.vmName, search.attacker, search.outIP) + 1);
                	sprintf(buf,"%s,%s,%s\n",search.vmName,search.attacker,search.outIP);
                	write(vmi_sock, buf, strlen(buf));
			free(buf);
		}
		else
			args->node->result = 1;

		free(search.vmName);
		free(search.attacker);
	} else {
		args->node->result = 0;
	}

	g_strfreev(key_dst);
	return;
}

void mod_vmi(struct mod_args *args) {

        gchar *mode;
         /*! get the backup file for this module */
        if ( NULL ==    (mode = (gchar *)g_hash_table_lookup(args->node->arg, "mode"))) {
                /*! We can't decide */
                args->node->result = -1;
                g_printerr("%s mandatory argument 'mode' undefined (back/control)!\n", H(args->pkt->conn->id));
                return;
        }

	if(!strcmp(mode,"pick"))
		mod_vmi_pick(args);
	else
	if(!strcmp(mode,"back"))
		mod_vmi_back(args);
	else
	if(!strcmp(mode,"control"))
		mod_vmi_control(args);
	else
		args->node->result=-1;
}

//////////////////////

int init_mod_vmi() {

	gchar *vmi_server_ip, *vmi_server_port;

        if(NULL == (vmi_server_ip=(gchar *)g_hash_table_lookup(config,"vmi_server_ip"))) {
                // Not defined so skipping init
                return 0;
        }

        if(NULL == (vmi_server_port=(gchar *)g_hash_table_lookup(config,"vmi_server_port"))) {
                errx(1,"%s: VMI Server port not defined!!\n",__func__);
        }

	g_printerr("%s Init mod vmi\n", H(22));

	/* socket: create the socket */
	vmi_sock = socket(AF_INET, SOCK_STREAM, 0);
    	if (vmi_sock < 0)
        	errx(1, "%s: ERROR opening socket",__func__);

	/* build the server's Internet address */
	bzero((char *) &vmi_addr, sizeof(vmi_addr));
    	vmi_addr.sin_family = AF_INET;
    	vmi_addr.sin_addr.s_addr = inet_addr(vmi_server_ip);
    	vmi_addr.sin_port = htons(atoi(vmi_server_port));

	/* connect: create a connection with the server */
    	if (connect(vmi_sock, (struct sockaddr *)&vmi_addr, sizeof(vmi_addr)) < 0)
		errx(1, "%s: ERROR connecting", __func__);

	int n = write(vmi_sock, "hello\n", strlen("hello\n"));
	if (n < 0)
      		errx(1,"%s ERROR writing to socket\n",__func__);

	char buf[100];
    	bzero(buf, 100);
    	n = read(vmi_sock, buf, 100);
	if(n<0 || strcmp(buf, "hi\n\r"))
		errx(1,"%s Error receiving from Honeymon!\n",__func__);
    	else
    		printf("%s VMI-Honeymon is active, query VM states..\n", H(22));

	vmi_vms=g_tree_new_full((GCompareDataFunc)intcmp, NULL, (GDestroyNotify)noop, (GDestroyNotify)free_vmi_vm);
        g_ptr_array_foreach(targets, (GFunc)build_vmi_vms, (gpointer)&vmi_sock);

	bannedIPs=g_tree_new_full((GCompareDataFunc)strcmp, NULL, (GDestroyNotify)free, (GDestroyNotify)free);

	return 0;
}
