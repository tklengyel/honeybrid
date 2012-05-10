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

/*! \file mod_source.c
 * \brief Source IP based filtering Module for honeybrid Decision Engine
 *
 * This module is called by a boolean decision tree to filter attacker based on their IP address
 *
 \author Robin Berthier 2009
 */

#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "tables.h"
#include "modules.h"
#include "netcode.h"

GThread *vmi_com_thread;
GStaticRWLock vmi_lock;
GQueue *vmi_send, *vmi_recv;
int vmi_com_count;
int vmi_session_start;
int last_check;
int IP_last_seen;
char *vmi_user;

int vmi_sock;                   /* Socket descriptor */
struct sockaddr_in vmi_addr;    /* VMI server address */
unsigned short vmi_port;    /* VMI server port */

struct vmi_msg {
	int com_id;
	char *vmname;
	char *command;
	int result;
};

void free_vmi_msg(gpointer data) {
        struct vmi_msg *tofree = (struct vmi_msg *)data;
	if(tofree->vmname!=NULL)
		free(tofree->vmname);
	if(tofree->command!=NULL)
		free(tofree->command);
        free(tofree);
}

int assign_vm(char *key) {

	g_queue_foreach(vmi_send,(GFunc)free_vmi_msg,NULL);
        g_queue_foreach(vmi_recv,(GFunc)free_vmi_msg,NULL);

        g_queue_clear(vmi_send);
        g_queue_clear(vmi_recv);

        vmi_user=(char *)malloc(strlen(key));
        strcpy(vmi_user,key);

	GTimeVal t;
        g_get_current_time(&t);
        gint now = t.tv_sec;
	last_check = now;
	IP_last_seen = now;
        vmi_session_start = now;

	return 1;
}

void check_vm_state(gchar *vmname) {

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	int conn_expired=0;
	// if IP haven't sent anything in a minute or if the entire session is 10 minutes old
	if(now-IP_last_seen>=60 || now-vmi_session_start >= 600)
		conn_expired=1;
	else
		conn_expired=0;

	// check msg queues
	if(!g_queue_is_empty(vmi_send)) {
		// msg waiting to be sent
	} else
	if(g_queue_is_empty(vmi_send) && !g_queue_is_empty(vmi_recv)) {
		// got message, check it
		struct vmi_msg *msg = (struct vmi_msg *)g_queue_pop_head(vmi_recv);
		if(msg->result==1 || msg->result == 3) {
			// vm was reset
			g_printerr("%s VM is now free because of a reset!\n",H(22));
			free(vmi_user);
			vmi_user=NULL;
		} else
		if(msg->result == 0 && conn_expired) {
			// no change was detected and connection expired
			g_printerr("%s VM is now free because of timeout and no change!\n",H(22));
			free(vmi_user);
			vmi_user=NULL;
		} else {
			// ERROR
			g_printerr("%s ERROR in VMI Honeymon!\n",H(22));
		}
		free(msg);
	} else
	if(g_queue_is_empty(vmi_send) && g_queue_is_empty(vmi_recv)) {
		// nothing
		if(conn_expired) {
			// do a final check
			g_printerr("%s Sending check request to VMI because connection expired!\n",H(22));
			struct vmi_msg *command = (struct vmi_msg *)malloc(sizeof(struct vmi_msg));
			command->com_id=vmi_com_count;
			command->vmname=(char *)malloc(strlen(vmname));
			strcpy(command->vmname,vmname);
			command->command=(char *)malloc(6*sizeof(char));
			strcpy(command->command,"check");

			g_queue_push_head(vmi_send, command);
		}
	}
}

/*
 * Communication thread with VMI-Honeymon
 */
void vmi_com() {
	while(1) {
		int doSleep=0;
		g_static_rw_lock_writer_lock(&vmi_lock);

		if(!g_queue_is_empty(vmi_send) && g_queue_is_empty(vmi_recv)) {
			// Query honeymon

			if ((vmi_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0
				|| connect(vmi_sock, (struct sockaddr *) &vmi_addr, sizeof(vmi_addr)) < 0) {
		                g_printerr("%s: Couldn't connect to VMI Honeymon\n", H(22));
		        } else {

				/* Get the msg from the queue and format it into string */
				struct vmi_msg *command = (struct vmi_msg *)g_queue_pop_head(vmi_send);
				char *send_str = (char *)malloc(100*sizeof(char));

				g_printerr("\n\n%s Building tcp message with %i,%s,%s\n\n",H(22),command->com_id,command->vmname,command->command);
				g_snprintf(send_str, 100, "%i,%s,%s,%s\n\r", command->com_id, command->vmname, command->command, vmi_user);

    				if (send(vmi_sock, send_str, strlen(send_str), 0) != strlen(send_str)) {
					g_printerr("%s Couldn't send message to VMI server\n", H(22));
				} else {
					g_printerr("%s Command sent to VMI: %s", H(22),send_str);

					GTimeVal t;
        				g_get_current_time(&t);
        				last_check = (t.tv_sec);

					/* Now let's wait for an answer */
					char *vmi_buffer = (char *)malloc(100*sizeof(char));
					memset( vmi_buffer, '\0', 100);

	        			if (recv(vmi_sock, vmi_buffer, 100, 0) <= 0) {
						g_printerr("%s Didn't get any message back!\n", H(22));
					} else {
						g_printerr("%s Received from VMI %s\n", H(22),vmi_buffer);

						struct vmi_msg *msg = (struct vmi_msg *)malloc(sizeof(struct vmi_msg));

						char *ptr = strtok(vmi_buffer, ",");
						int count=-1;
						while(ptr != NULL) {
							count++;

                                           	     	if(count==0) {
								msg->com_id=atoi(ptr);
		                                     	} else
                                                	if(count==1) {
								msg->vmname=(char *)malloc(strlen(ptr));
                                                        	strcpy(msg->vmname,ptr);
                                                	} else
                                                	if(count==2) {
                                                        	msg->result = atoi(ptr);
                                                	}

                                                	ptr = strtok(NULL, ",");
						}

						if(msg->com_id==command->com_id) {
							g_queue_push_head(vmi_recv,(gpointer) msg);
							vmi_com_count++;
						} else {
							free_vmi_msg(msg);
							g_printerr("%s Couldn't parse the reply message!\n",H(22));
						}
					}
					free(vmi_buffer);
				}


				free_vmi_msg((gpointer)command);
				free(send_str);
				close(vmi_sock);
			}
		} else {
			doSleep=1;
		}
		g_static_rw_lock_writer_unlock(&vmi_lock);

		if(doSleep)
			sleep(1);
	}
}

/*
 * Create thread to connect to VMI-Honeymon and setup queues to communicate with main program
 */
int init_mod_vmi() {

	gchar *vmi_server_ip, *vmi_server_port;

	if(NULL == (vmi_server_ip=(gchar *)g_hash_table_lookup(config,"vmi_server_ip"))) {
		// Not defined so skipping init
		return 0;
        }

	if(NULL == (vmi_server_port=(gchar *)g_hash_table_lookup(config,"vmi_server_port"))) {
                errx(1,"%s: VMI Server port not defined!!\n",__func__);
        }

	/* Construct the server address structures */
    	memset(&vmi_addr, 0, sizeof(vmi_addr));     			/* Zero out structure */
    	vmi_addr.sin_family      = AF_INET;             		/* Internet address family */
    	vmi_addr.sin_addr.s_addr = inet_addr(vmi_server_ip);   		/* Server IP address */
    	vmi_addr.sin_port        = htons(atoi(vmi_server_port)); 	/* Server port */

	if ((vmi_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0
                                || connect(vmi_sock, (struct sockaddr *) &vmi_addr, sizeof(vmi_addr)) < 0) {
        	errx(1,"%s: Couldn't connect to VMI Honeymon\n", __func__);
	} else {
		g_printerr("%s: Connected to VMI Honeymon!\n",H(22));
		close(vmi_sock);
	}

	g_static_rw_lock_init( &vmi_lock );

	vmi_send = g_queue_new();
	vmi_recv = g_queue_new();

	vmi_com_count=0;
	vmi_user=NULL;
	last_check=0;

	// create xmpp backup thread
        if( ( vmi_com_thread = g_thread_create_full (((void *)vmi_com), NULL, 0, TRUE, TRUE, 0, NULL)) == NULL)
                errx(1, "%s: Unable to start the VMI communication thread", __func__);
        else
                g_printerr("%s: VMI communication thread started\n", H(22));

	return 1;
}

void mod_vmi(struct mod_args *args)
{
	g_printerr("%s VMI Module called\n", H(args->pkt->conn->id));

	//int expiration = 24*3600; /* a day */

	GTimeVal t;
        g_get_current_time(&t);
        gint now = (t.tv_sec);

	/*! get the IP address from the packet */
	gchar **key_src,**key_dst;
	key_src = g_strsplit( args->pkt->key_src, ":", 0);
	key_dst =  g_strsplit(args->pkt->key_dst, ":", 2);

	//g_printerr("%s source IP is %s\n", H(args->pkt->conn->id), key_src[0]);

	gchar *mode;
	gchar *vmname;
         /*! get the backup file for this module */
        if ( NULL ==    (mode = (gchar *)g_hash_table_lookup(args->node->arg, "mode"))) {
                /*! We can't decide */
                args->node->result = -1;
                g_printerr("%s mandatory argument 'mode' undefined (back/control)!\n", H(args->pkt->conn->id));
                return;
        }
	if ( NULL ==    (vmname = (gchar *)g_hash_table_lookup(args->node->arg, "vmname"))) {
                /*! We can't decide */
                args->node->result = -1;
                g_printerr("%s mandatory argument 'vmname'!\n", H(args->pkt->conn->id));
                return;
        }

	if(g_static_rw_lock_writer_trylock(&vmi_lock)) {

		g_printerr("%s Got the lock for VMI\n",H(22));

		if(vmi_user != NULL)
			check_vm_state(vmname);

		if(strcmp(mode,"back")==0) {
			if(vmi_user==NULL) {
				if(args->pkt->packet.ip->protocol==6) {
					g_printerr("%s Vm is free, accept!\n",H(22));
					assign_vm(key_src[0]);
					args->node->result =  1;
				} else {
					g_printerr("%s Vm is free, but I don't like this connection\n", H(22));
				}
			} else
			if(strcmp(key_src[0],vmi_user)!=0) {
				// vm is used, decline
				g_printerr("%s Vm is in use right now by %s\n",H(22),vmi_user);
				args->node->result = 0;
			} else {
				args->node->result = 1;
				IP_last_seen=now;
				g_printerr("%s Vm is used by this IP: %s and you are: %s, accepted!\n",H(22), vmi_user, key_src[0]);
			}
		}

		if(strcmp(mode,"control")==0) {
			if(vmi_user==NULL) {
				if(args->pkt->origin==HIH) {
					// No forwarded session and the VM is generating outbound traffic?
					g_printerr("%s No forwarded session and the VM is generating outbound traffic\n", H(22));
					args->node->result=0;
				} else {
					args->node->result=1;
				}
			} else
			if(strcmp(key_src[0],vmi_user)==0 || strcmp(key_dst[0],vmi_user)==0) {
				// packet is part of a forwarded connection

				IP_last_seen=now;
				/*if(now-last_check>60 && g_queue_is_empty(vmi_send)) {
					// haven't checked in a minute, do it
					g_printerr("%s Initiating VM check from Control because of timeout!\n", H(22));
					struct vmi_msg *command = (struct vmi_msg *)malloc(sizeof(struct vmi_msg));
                                	command->com_id=vmi_com_count;
                                	command->vmname=(char *)malloc(strlen(vmname));
                                	strcpy(command->vmname,vmname);
                                	command->command=(char *)malloc(6*sizeof(char));
                                	strcpy(command->command,"check");

                                	g_queue_push_head(vmi_send, command);
				}*/

				args->node->result=1;
			} else
			if(args->pkt->origin==HIH) {
               			// Cought pkt from HIH thats going somewhere other then the attacker!
				// Let it go for a while or dump VM right away?
				g_printerr("%s Cought a unrecognized connection from the HIH during a forwaded session!\n",H(22));

				// Clearing the queue, dump has priority
				if(!g_queue_is_empty(vmi_send)) {
					g_queue_foreach(vmi_send,(GFunc)free_vmi_msg,NULL);
					g_queue_clear(vmi_send);
				}

				struct vmi_msg *command = (struct vmi_msg *)malloc(sizeof(struct vmi_msg));
	                        command->com_id=vmi_com_count;
	                        command->vmname=(char *)malloc(strlen(vmname));
  	                      	strcpy(command->vmname,vmname);
        	                command->command=(char *)malloc(5*sizeof(char));
                	        strcpy(command->command,"dump");

                        	g_queue_push_head(vmi_send, command);

				args->node->result=0;
			} else {
				// unrelated
				args->node->result=1;
			}
		}

		g_static_rw_lock_writer_unlock(&vmi_lock);
	} else {
		// VMI comm is locked
		if(strcmp(mode,"back")==0) {
			g_printerr("%s VMI is locked\n",H(22));
			args->node->result = 0;
			return;
		}
		if(strcmp(mode,"control")==0) {
			if(vmi_user == NULL) {
				// routine comm queue check lock?
				if(args->pkt->origin==HIH) {
					// WEIRD
					args->node->result=0;
				} else {
					args->node->result=1;
				}
				return;
			} else
			if(strcmp(key_src[0],vmi_user)==0 || strcmp(key_dst[0],vmi_user)==0) {
				// this packet is from the forwarded attacker and we are checking right now
				IP_last_seen=now;
				args->node->result = 0;
				return;
			} else
			if(args->pkt->origin==HIH) {
				// HOW IS THIS POSSIBLE?
				args->node->result = 0;
				return;
			} else {
				// unrelated
				args->node->result = 1;
				return;
			}
		}
	}

	return;
}
