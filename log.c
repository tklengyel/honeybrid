/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <jvehent@umd.edu> for the University of Maryland)
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

/*! \file log.c
    \brief Log function for honeybrid

    \author Julien Vehent, 2007
    \author Thomas Coquelin, 2008
 */

#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>

#include "tables.h"
#include "log.h"

/*!
 \def last_rotation
 \brief last timestamp the log file was rotated
 */
unsigned long last_rotation;

/*! 
 \Def file descriptor to log connections
 */

static FILE *logfd;

/*! honeylog
 *
 \brief add a log entry in the singly linked list
 *
 \param[in] static string pointer
 \param[in] dynamicaly allocated string pointer
 \param[in] log level of event
 \param[in] connection id
 *
 \return OK when done, NOK on failure
 */
int honeylog(char *sdata, char *ddata, int level, unsigned id)
{
	/*!filter events upon their log level*/

	/*
	char* log_level = g_hash_table_lookup(config,"log_level");
	if(log_level == NULL)
		log_level = "3";
	if(level> atoi(log_level))
	*/
	if(level > LOG_LEVEL)
	{
		if(ddata != NULL)
			free(ddata);
	}
	else
	{
		struct tm *tm;
		struct timeval tv;
		struct timezone tz;
		struct log_event *event = malloc(sizeof(struct log_event));
		gettimeofday(&tv, &tz);
		tm=localtime(&tv.tv_sec);
		if (tm == NULL) {
			perror("localtime");
			return NOK;
		}
		event->sdata = sdata;
		event->ddata = ddata;
		event->level = level;
		event->id = id;
		event->curtime = malloc(30);
		//strftime(event->curtime, sizeof(curtime), "%F %T", tm);
		sprintf(event->curtime,"%d-%02d-%02d %02d:%02d:%02d.%.6d", (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec);

	/*! store the address of the payload as a new entry of the list
	 *
	 * (set up a lock to protect the writing)
	 */
		g_static_rw_lock_writer_lock (&loglock);
		log_list = g_slist_append(log_list, event);
		g_static_rw_lock_writer_unlock (&loglock);
	}
	return OK;
}

/*! write_log
 *
 \brief wake up every 10s from a thread, check the singly linked list and write the new entries to syslog
 *
 */
void write_log()
{
	struct log_event *event;
	int syslog_enabled = 0;
	if ( NULL != strstr(g_hash_table_lookup(config,"output"),"1") )
		syslog_enabled = 1;

	/*! infinite loop that check new entries in the list and write them
	 */
	while( threading == OK ){
	/*! check for new log events every 1 ms
	 */
	 g_usleep(1000);
	 //g_usleep(100);

 	 while ( g_slist_length(log_list) > 0 )
	 {
		/*! get the value */
		/*! process it
		 *
		 * log pattern is :
		 * <timestamp>;<id>;<log string>;
		 */
		event = g_slist_nth_data (log_list, 0);
		if(event->sdata != NULL && event->ddata == NULL)
		{
			//if ( NULL != strstr(g_hash_table_lookup(config,"output"),"1") )
			if ( syslog_enabled == 1)
				/*! log to syslog */
				syslog(LOG_INFO | LOG_USER, "%s id:%5u %s",event->curtime, event->id, event->sdata);
			else
				/*! or log to stdout */
				g_print("%s;id:%5u;%s",event->curtime, event->id, event->sdata);
		}
		else if(event->sdata == NULL && event->ddata != NULL)
		{
			//if ( NULL != strstr(g_hash_table_lookup(config,"output"),"1") )
			if ( syslog_enabled == 1)
				/*! log to syslog */
				syslog(LOG_INFO | LOG_USER, "%s id:%5u %s",event->curtime, event->id, event->ddata);
			else
				/*! or log to stdout */
				g_print("%s;id:%5u;%s",event->curtime, event->id, event->ddata);
			free(event->ddata);
		}
		else
			g_print("write_log(): Incorrect event\n");
		/*! free the memory */
		free(event->curtime);
		g_static_rw_lock_writer_lock (&loglock);
		log_list = g_slist_delete_link(log_list, log_list);
		g_static_rw_lock_writer_unlock (&loglock);
		free(event);
	 }
	}
}

int close_log_file(void)
{
	return fclose(logfd);
}

/*! open log file
 \brief open the file honeybrid.log
 */
int open_log_file(void)
{
	char *logbuf;
	if (0 != chdir(g_hash_table_lookup(config,"log_directory")))
        {
		logbuf = malloc(256);
		sprintf(logbuf, "open_log_file()\tError! Unable to move to log directory -> %s\n", (char *) g_hash_table_lookup(config,"log_directory"));
		L(NULL, logbuf, LOG_ALL, LOG_LOG);
                return -1;
        }

	if (NULL == g_hash_table_lookup(config,"log_file")) {
		L("open_log_file()\tError! No log file specified in the config\n", NULL, LOG_ALL, LOG_LOG);
                return -1;
        }
	if (NULL == (logfd = fopen(g_hash_table_lookup(config,"log_file"),(char *) "a"))) {
		return -1;
	} 

	/*! Enable line buffer */
	setlinebuf(logfd);

	if (0 != chdir(g_hash_table_lookup(config,"exec_directory")))
        {
		logbuf = malloc(256);
		sprintf(logbuf, "open_log_file()\tError! Unable to move to exec directory -> %s\n", (char *) g_hash_table_lookup(config,"exec_directory"));
		L(NULL, logbuf, LOG_ALL, LOG_LOG);
        }

	return 0;
}

/*! rotate_log_file
 *\brief rotate the file honeybrid.log every hour
 */
//void rotate_log(int signal_nb, void *siginfo, void *context)
void rotate_log(int signal_nb)
{
	L("rotate_log()\tCalled\n", NULL, LOG_ALL, LOG_LOG);

	unsigned long timestamp;
	//char *logfile_name;
	//char *new_name;
	GString *logfile_name;
	GString *new_name;
	char *logbuf;

	struct tm *tm;
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        tm=localtime(&tv.tv_sec);
        if (tm == NULL) {
               perror("localtime");
               return;
        }

	timestamp = 	( (tm->tm_year)*(1000000)
			+ (1+tm->tm_mon)*(10000)
			+ (tm->tm_mday)*(100)
			+ (tm->tm_hour) );

	if (last_rotation == 0)
	{
		last_rotation = timestamp;

		logbuf = malloc(256);
		sprintf(logbuf,"rotate_log()\tlast_rotation initialized to %lu\n", last_rotation);
		L(NULL, logbuf, 4, LOG_LOG);

		return;
	}

	if (timestamp > last_rotation || signal_nb > 0)
	{
		if (signal_nb > 0) {
			L("rotate_log()\tSIGUSR1 received, rotating log...\n", NULL, LOG_MED, LOG_LOG);
		} else {
			L("rotate_log()\tTime to rotate the log...\n", NULL, LOG_MED, LOG_LOG);
		}

		fclose(logfd);

		//logfile_name = malloc(sizeof(g_hash_table_lookup(config,"log_file"))+1);
		//logfile_name = malloc(512);
		///logfile_name = g_new0(char, 256);
		///logfile_name = g_hash_table_lookup(config,"log_file");
		///new_name = malloc(sizeof(logfile_name) + 64);
	        ///sprintf(new_name,"%s.%d%02d%02d_%02d%02d", logfile_name, (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min);
		logfile_name = g_string_new( g_hash_table_lookup(config,"log_file") );
		#ifdef DEBUG
		g_print("rotate_log()\tlogfile_name is %s\n", logfile_name->str);
		#endif

		new_name = g_string_new("");
		g_string_printf( new_name, "%s.%d%02d%02d_%02d%02d", logfile_name->str, (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min);

		logbuf = malloc(512);
		sprintf(logbuf, "rotate_log()\tRotating log file from %s to %s\n", logfile_name->str, new_name->str);
		L(NULL, logbuf, LOG_HIGH, LOG_LOG);

		chdir(g_hash_table_lookup(config,"log_directory"));
		
		if (rename(logfile_name->str, new_name->str)) {
			L("rotate_log()\tERROR: can't rename log file!\n", NULL, LOG_MED, LOG_LOG);
		}

		//i = open(logfile_name, O_RDWR | O_CREAT, 0640);
		logfd = fopen(g_hash_table_lookup(config,"log_file"), (char *)"a");

		chdir(g_hash_table_lookup(config,"exec_directory"));

		///g_free(logfile_name);
		///free(new_name);
		g_string_free(logfile_name, TRUE);
		g_string_free(new_name, TRUE);

		/*! The last step is to update last_rotation
		 */
		last_rotation = timestamp;

		logbuf = malloc(256);
		sprintf(logbuf,"rotate_log()\tLog file re-opened. last_rotation updated to %lu\n", last_rotation);
		L(NULL, logbuf, LOG_HIGH, LOG_LOG);


	}

	return;
}

/*! connection_stat
 *\brief compile a single line of final statistics for every connection handled by honeybrid:
 * Basic flow information: start timestamp, source IP, source Port, destination IP, destination Port, protocol, cumulative flags if TCP
 * INVALID information: duration, reason, packet, byte
 * INIT information: duration, packet, byte
 * DECIDE information: duration, rule, packet id, high interaction ip and port
 * REPLAY information: duration, problem, packet, byte
 * FORWARD information: duration, packet, byte
 */

void connection_stat(struct conn_struct *conn)
{

	/*! if log rotation is configured, then we call rotate_log()
	 */
	if ( NULL != strstr(g_hash_table_lookup(config,"log_rotation"),"1") ) {
		//rotate_log(0, NULL, NULL);
		rotate_log(0);
	}

	gchar **tuple;
	tuple = g_strsplit( conn->key, ":", 0);

	GString *proto  = g_string_new("");
	switch( conn->protocol ) {
		case 6:
			g_string_printf(proto,"TCP");
			break;
		case 17:
			g_string_printf(proto,"UDP");
			break;
		default:
			g_string_printf(proto,"%d",conn->protocol);
			break;
	}

	GString *status = g_string_new("");
	switch( conn->state ) {
		case INIT:
			g_string_printf(status,"INIT");
			break;
		case DECISION:
			g_string_printf(status,"DECISION");
			break;
		case REPLAY:
			g_string_printf(status,"REPLAY");
			break;
		case FORWARD:
			g_string_printf(status,"FORWARD");
			break;
		case PROXY:
			g_string_printf(status,"PROXY");
			break;
		case DROP:
			g_string_printf(status,"DROP");
			break;
		default:
			g_string_printf(status,"INVALID");
	}

	gint i;
	GString *status_info[6];
	gdouble lasttime = conn->start_microtime;
	gdouble duration = 0.0;
	for( i = INIT; i<=PROXY; i++) {
		status_info[i] = g_string_new("");
		if ( i <= conn->state ) {
			if (conn->stat_time[i] > 0) {
				duration = (conn->stat_time[i] - lasttime);
				lasttime = conn->stat_time[i];
			} else {
				duration = 0.0;
			}
			if ( i == REPLAY && conn->replay_problem > 0 ) {
				g_string_printf( status_info[i], "%.3f|%d|%d|error:%d", duration, conn->stat_packet[i], conn->stat_byte[i], conn->replay_problem);
			} else if ( i == DECISION ) {
				g_string_printf( status_info[i], "%.3f|%s", duration, conn->decision_rule->str);
			} else {
				g_string_printf( status_info[i], "%.3f|%d|%d", duration, conn->stat_packet[i], conn->stat_byte[i]);
			}
		} else {
			if ( i == REPLAY )
				g_string_printf( status_info[i], ".|.|.|.");
			else if ( i == DECISION )
				g_string_printf( status_info[i], ".|.");
			else
				g_string_printf( status_info[i], ".|.|.");
		}
	}

	gdouble total_duration = (lasttime - conn->start_microtime);

	/*
	GString *decision_info = g_string_new(".");
	if (conn->state >= DECISION) {
		g_string_printf(decision_info, "%d:%s", conn->decision_packet_id, conn->decision_rule->str);
	}
	*/
	
	char *logbuf = malloc(1024);	//1024 might be too short!

	/*! Output according to the format configured */
	if ( NULL != strstr(g_hash_table_lookup(config,"log_format"),"csv") ) {
		sprintf(logbuf,"%s,%.3f,%s,%s,%s,%s,%s,%d,%d,%s,%d,%s,%s,%s,%s,%s\n", conn->start_timestamp->str, total_duration, proto->str, tuple[0], tuple[1], tuple[2], tuple[3], conn->total_packet, conn->total_byte, status->str, conn->id, 
		//status_info[INVALID]->str,
		status_info[INIT]->str,
		status_info[DECISION]->str,
		status_info[REPLAY]->str,
		status_info[FORWARD]->str,
		status_info[PROXY]->str
		);
        } else {
		sprintf(logbuf,"%s %.3f %s %s:%s -> %s:%s %d %d %s ** %d %s %s %s %s %s\n", conn->start_timestamp->str, total_duration, proto->str, tuple[0], tuple[1], tuple[2], tuple[3], conn->total_packet, conn->total_byte, status->str, conn->id, 
		//status_info[INVALID]->str,
		status_info[INIT]->str,
		status_info[DECISION]->str,
		status_info[REPLAY]->str,
		status_info[FORWARD]->str,
		status_info[PROXY]->str
		);
	}	
	///g_printerr("%s",logbuf);	
	fprintf(logfd, "%s", logbuf);
	
	g_free(logbuf);
	g_strfreev(tuple);	/// ROBIN - 20090326-1007 according to valgrind output
	//g_free(status_info);	/// seg fault
        //L(NULL,logbuf,1,conn->id);
}
